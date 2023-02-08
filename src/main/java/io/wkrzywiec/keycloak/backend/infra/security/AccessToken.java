package io.wkrzywiec.keycloak.backend.infra.security;

import static java.util.Objects.isNull;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collection;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

public record AccessToken(String value) {

    public static final String BEARER = "Bearer ";

    public String getValue() {
        return value;
    }

    public Collection<? extends GrantedAuthority> getAuthorities() {
        JsonObject payloadAsJson = getPayloadAsJsonObject();
        JsonArray jobj = new JsonArray();
        JsonObject item = new JsonObject();
           jobj.add("view-profile");
           jobj.add( "manage-account");
        item.add("roles",jobj);
        payloadAsJson.add("realm_access", item);
        
        
        System.out.println("payloadAsJson -->> "+payloadAsJson);
        
        /**return StreamSupport.stream(
                payloadAsJson.getAsJsonObject("realm_access").getAsJsonArray("roles").spliterator(), false)
        .map(JsonElement::getAsString)
        .map(SimpleGrantedAuthority::new)
        .collect(Collectors.toList());**/

        return StreamSupport.stream(
                        payloadAsJson.getAsJsonObject("realm_access").getAsJsonArray("roles").spliterator(), false)
                .map(JsonElement::getAsString)
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }

    public String getUsername() {
        JsonObject payloadAsJson = getPayloadAsJsonObject();

        return Optional.ofNullable(
                        payloadAsJson.getAsJsonPrimitive("user_name").getAsString())
                .orElse("");
    }

    private JsonObject getPayloadAsJsonObject() {
        DecodedJWT decodedJWT = decodeToken(value);
        return decodeTokenPayloadToJsonObject(decodedJWT);
    }

    private DecodedJWT decodeToken(String value) {
        if (isNull(value)) {
            throw new InvalidTokenException("Token has not been provided");
        }
        return JWT.decode(value);
    }

    private JsonObject decodeTokenPayloadToJsonObject(DecodedJWT decodedJWT) {
        try {
            String payloadAsString = decodedJWT.getPayload();
            return new Gson().fromJson(
                    new String(Base64.getDecoder().decode(payloadAsString), StandardCharsets.UTF_8),
                    JsonObject.class);
        } catch (RuntimeException exception) {
            throw new InvalidTokenException("Invalid JWT or JSON format of each of the jwt parts", exception);
        }
    }
}
