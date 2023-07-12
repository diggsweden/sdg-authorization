package se.digg.sdg.sample.client.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;

import net.minidev.json.JSONObject;

public class DisplayUtils {

  private static ObjectMapper objectMapper = new ObjectMapper();

  public static String toJsonDisplayString(final JWT jwt) {
    try {
      final JSONObject jsonObject = new JSONObject(jwt.getJWTClaimsSet().toJSONObject());
      return objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(jsonObject);
    }
    catch (final Exception e) {
      return "Failed to parse";
    }
  }
  
  public static String toJsonDisplayString(final JWTClaimsSet jwt) {
    try {
      final JSONObject jsonObject = new JSONObject(jwt.toJSONObject());
      return objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(jsonObject);
    }
    catch (final Exception e) {
      return "Failed to parse";
    }
  }

  private DisplayUtils() {
  }
}
