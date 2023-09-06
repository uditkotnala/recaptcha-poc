package com.ps.recaptcha.util;

import com.ps.recaptcha.controller.CaptchaController;
import com.ps.recaptcha.model.GoogleRecaptchaResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

@Service
public class CaptchaUtil {

    private static final Logger logger = LoggerFactory.getLogger(CaptchaController.class);

    @Value("${google.recaptcha.site-verify-url}")
    private String siteVerifyUrl;

    public boolean verifyReCaptcha(String captchaResponse, String recaptchaSecretKey) {
        RestTemplate restTemplate = new RestTemplate();
        // Create the request headers with content type application/x-www-form-urlencoded
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        GoogleRecaptchaResponse googleResponse = null;
        try {
            // Create the request parameters
            MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
            params.add("secret", recaptchaSecretKey);
            params.add("response", captchaResponse.replace(",", ""));
            // Create the HTTP request entity
            HttpEntity<MultiValueMap<String, String>> requestEntity = new HttpEntity<>(params, headers);
            // Send a POST request to Google's reCAPTCHA verification endpoint with the parameters
            ResponseEntity<GoogleRecaptchaResponse> responseEntity = restTemplate.exchange(siteVerifyUrl, HttpMethod.POST, requestEntity, GoogleRecaptchaResponse.class);
            googleResponse = responseEntity.getBody();

        } catch (HttpClientErrorException e) {
            // Handle HTTP error responses (e.g., 400 Bad Request)
            logger.error("HTTP error during reCAPTCHA verification. Status code: {}, Response: {}", e.getStatusCode(), e.getResponseBodyAsString());
            return false;
        } catch (Exception e) {
            // Handle other exceptions
            logger.error("An error occurred during reCAPTCHA verification: {}", e.getMessage(), e);
            return false;
        }
        return googleResponse != null && googleResponse.isSuccess();
    }
}
