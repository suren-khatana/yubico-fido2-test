package com.example;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.yubico.fido.metadata.AAGUID;
import com.yubico.fido.metadata.FidoMetadataService;
import com.yubico.fido.metadata.MetadataBLOBPayload;
import com.yubico.fido.metadata.MetadataBLOBPayloadEntry;
import com.yubico.fido.metadata.MetadataStatement;
import com.yubico.webauthn.data.ByteArray;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.keys.X509Util;
import org.jose4j.lang.JoseException;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.time.LocalDate;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class FidoMetaDataServiceProvider {
    private static final ObjectMapper mapper = createObjectMapper();
    private static final AtomicReference<FidoMetadataService> cachedService = new AtomicReference<>();

    private static final List<String> MDS_ENDPOINTS = List.of(
            "https://mds3.fido.tools/execute/83defb8814c6be643ecdf13a78323377e2dd50e5d0939aff3c1e131fe1fd7091",
            "https://mds3.fido.tools/execute/281f65ffc9c84251b7ebe04b0fb3b1812392cd3354ac25eab04a59b4c73953d6",
            "https://mds3.fido.tools/execute/c4e9999467fcfe635d88af0126a8ed843d4b0d9cb06f3936482f24484ea23185",
            "https://mds3.fido.tools/execute/70ca87e4e27466f8efc0da76e31b6c159ed4c7393845b3a913adf55001874810",
            "https://mds3.fido.tools/execute/0e88691e4d9612e0040e3fb65e586c0cebd2947e4d5d69b4655112406c3ca754"
    );

    private static ObjectMapper createObjectMapper() {
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.registerModule(new JavaTimeModule());
        objectMapper.registerModule(new SimpleModule().addDeserializer(AAGUID.class, new AAGUIDDeserializer()));
        objectMapper.configure(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES, false);
        objectMapper.configure(DeserializationFeature.FAIL_ON_MISSING_CREATOR_PROPERTIES, false);
        return objectMapper;
    }

    public static FidoMetadataService getFidoMetadataService() {
        return cachedService.updateAndGet(service -> service != null ? service : fetchAndBuildFidoMetadataService());
    }

    private static FidoMetadataService fetchAndBuildFidoMetadataService() {
        System.out.println("Fetching Fido Metadata Service...");

        // Fetch valid metadata from MDS endpoints
        Set<MetadataBLOBPayloadEntry> validEntries = MDS_ENDPOINTS.parallelStream()
                .map(FidoMetaDataServiceProvider::processMdsEndpoint)
                .filter(Objects::nonNull)  // Ensure only valid metadata is processed
                .flatMap(payload -> payload.getEntries().stream())
                .collect(Collectors.toSet());

        // Add metadata from local JSON files
        Set<MetadataBLOBPayloadEntry> localEntries = loadMetadataFromFiles("src/main/resources");
        validEntries.addAll(localEntries);

        if (validEntries.isEmpty()) {
            throw new RuntimeException("No valid metadata entries were loaded.");
        }

        MetadataBLOBPayload combinedPayload = MetadataBLOBPayload.builder()
                .entries(validEntries)
                .legalHeader("By using this test metadata service, you solemnly swear not to do evil!")
                .nextUpdate(LocalDate.of(2026, 2, 28))
                .build();

        System.out.println("Total valid metadata entries loaded (MDS + local) = " + validEntries.size());
        System.out.println("\n");

        try {
            return FidoMetadataService.builder().useBlob(combinedPayload).build();
        } catch (Exception e) {
            throw new RuntimeException("Error initializing FIDO Metadata Service", e);
        }
    }


    private static Set<MetadataBLOBPayloadEntry> loadMetadataFromFiles(String directory) {
        try (Stream<Path> paths = Files.list(Path.of(directory))) {
            return paths.parallel()
                    .filter(path -> path.toString().endsWith(".json"))
                    .map(FidoMetaDataServiceProvider::readFileContent)
                    .filter(Objects::nonNull)
                    .map(FidoMetaDataServiceProvider::parseMetadataFromJson)
                    .filter(Objects::nonNull)
                    .collect(Collectors.toSet());
        } catch (IOException e) {
            System.out.println("Failed to list metadata files:" + e.getMessage());
            return Collections.emptySet();
        }
    }

    private static String readFileContent(Path path) {
        try {
            return Files.readString(path, StandardCharsets.UTF_8);
        } catch (IOException e) {
            // logger.warn("Failed to read file {}: {}", path.getFileName(), e.getMessage());
            System.out.println("Failed to read file");
            e.printStackTrace();
            return null;
        }
    }

    private static MetadataBLOBPayloadEntry parseMetadataFromJson(String json) {
        try {
            MetadataStatement metadataStatement = mapper.readValue(json, MetadataStatement.class);
            return MetadataBLOBPayloadEntry.builder()
                    .metadataStatement(metadataStatement)
                    .statusReports(Collections.emptyList())
                    .timeOfLastStatusChange(LocalDate.of(2020, 1, 10))
                    .build();
        } catch (IOException e) {
            System.out.println("Failed to parse metadata JSON " + e.getMessage());
            return null;
        }
    }


    private static MetadataBLOBPayload processMdsEndpoint(String url) {
        try {
            String jwt = callMetaDataEndpoint(url);
            if (jwt == null) {
                System.out.println("Failed to retrieve metadata from " + url);
                return null;
            }

            MetadataBLOBPayload payload = verifyAndParseMetadataBlob(jwt);
            System.out.println("Successfully loaded metadata from " + url);
            return payload;
        } catch (Exception e) {
            System.out.println("Failed to process MDS: " + url);
            System.out.println("Reason = " + e.getMessage());
            return null;
        }
    }


    private static MetadataBLOBPayload verifyAndParseMetadataBlob(String jwt) throws JoseException, JsonProcessingException {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setCompactSerialization(jwt);
        PublicKey publicKey = extractPublicKeyFromX5c(jws.getHeaders().getObjectHeaderValue("x5c"));
        jws.setKey(publicKey);
        if (!jws.verifySignature()) throw new JoseException("JWT signature verification failed");
        return mapper.readValue(jws.getPayload(), MetadataBLOBPayload.class);
    }

    private static PublicKey extractPublicKeyFromX5c(Object x5cHeader) throws JoseException {
        if (!(x5cHeader instanceof List<?> x5c) || x5c.isEmpty())
            throw new IllegalArgumentException("Invalid x5c header");
        return new X509Util().fromBase64Der((String) x5c.get(0)).getPublicKey();
    }

    private static String callMetaDataEndpoint(String url) {
        try (CloseableHttpClient httpClient = HttpClients.createDefault();
             CloseableHttpResponse response = httpClient.execute(new HttpGet(url))) {
            return response.getCode() == 200 ? EntityUtils.toString(response.getEntity()) : null;
        } catch (Exception e) {
            //  logger.warn("Error calling JWT endpoint {}: {}", url, e.getMessage());
            e.printStackTrace();
            return null;
        }
    }
}

class AAGUIDDeserializer extends JsonDeserializer<AAGUID> {
    @Override
    public AAGUID deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
        String uuidString = p.getText();
        if (uuidString.length() == 32) {
            uuidString = uuidString.replaceFirst(
                    "(\\w{8})(\\w{4})(\\w{4})(\\w{4})(\\w{12})",
                    "$1-$2-$3-$4-$5"
            );
        }
        UUID uuid = UUID.fromString(uuidString);
        ByteBuffer byteBuffer = ByteBuffer.wrap(new byte[16]);
        byteBuffer.putLong(uuid.getMostSignificantBits());
        byteBuffer.putLong(uuid.getLeastSignificantBits());

        return new AAGUID(new ByteArray(byteBuffer.array()));
    }
}
