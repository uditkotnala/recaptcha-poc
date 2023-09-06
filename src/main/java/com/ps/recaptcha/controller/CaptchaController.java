package com.ps.recaptcha.controller;


import com.ps.recaptcha.util.CaptchaUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

@Controller
public class CaptchaController {

    private static final Logger logger = LoggerFactory.getLogger(CaptchaController.class);

    @Autowired
    CaptchaUtil captchaUtil;

    @Value("${google.recaptcha.v-site-key}")
    private String recaptchaVisibleSiteKey;

    @Value("${google.recaptcha.inv-site-key}")
    private String recaptchaInvisibleSiteKey;

    @Value("${google.recaptcha.v-secret-key}")
    private String recaptchaVisibleSecretKey;

    @Value("${google.recaptcha.inv-secret-key}")
    private String recaptchaInvisibleSecretKey;

    @Value("${google.recaptcha.site-verify-url}")
    private String siteVerifyUrl;

    @GetMapping("/visible")
    public String index(Model model) {
        model.addAttribute("visibleSiteKey", recaptchaVisibleSiteKey);
        return "index";
    }

    @GetMapping("/invisible")
    public String home(Model model) {
        model.addAttribute("invisibleSiteKey", recaptchaInvisibleSiteKey);
        return "home";
    }

    @PostMapping("/verify")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> verifyCaptcha(@RequestParam(name = "g-recaptcha-response") String captchaResponse) {
        Map<String, Object> response = new HashMap<>();
        try {
            // Verify reCAPTCHA
            boolean isCaptchaValid = captchaUtil.verifyReCaptcha(captchaResponse, recaptchaVisibleSecretKey);
            if (isCaptchaValid) {
                response.put("success", true);
                response.put("message", "reCAPTCHA verification successful");
                logger.info("reCAPTCHA verification successful");
            } else {
                response.put("success", false);
                response.put("message", "reCAPTCHA verification failed");
                logger.warn("reCAPTCHA verification failed");
            }
        } catch (Exception e) {
            // Handle exceptions
            logger.error("Error during reCAPTCHA verification: {}", e.getMessage(), e);
            response.put("success", false);
            response.put("message", "An error occurred during reCAPTCHA verification");
        }
        return ResponseEntity.ok(response);
    }

    @PostMapping({"/submit-invisible", "/submit-visible"})
    @ResponseBody
    public ResponseEntity<Map<String, Object>> verifyAllCaptcha(@RequestParam(name = "g-recaptcha-response") String captchaResponse, HttpServletRequest request) {
        Map<String, Object> response = new HashMap<>();
        try {
            String secretKey = "";
            if(request.getRequestURI().contains("invisible")) {
                secretKey = recaptchaInvisibleSecretKey;
            } else {
                secretKey = recaptchaVisibleSecretKey;
            }
            // Verify reCAPTCHA
            boolean isCaptchaValid = captchaUtil.verifyReCaptcha(captchaResponse, secretKey);
            if (isCaptchaValid) {
                response.put("success", true);
                response.put("message", "reCAPTCHA verification successful");
                logger.info("reCAPTCHA verification successful");
            } else {
                response.put("success", false);
                response.put("message", "reCAPTCHA verification failed");
                logger.warn("reCAPTCHA verification failed");
            }
        } catch (Exception e) {
            // Handle exceptions
            logger.error("Error during reCAPTCHA verification: {}", e.getMessage(), e);
            response.put("success", false);
            response.put("message", "An error occurred during reCAPTCHA verification");
        }
        return ResponseEntity.ok(response);
    }
}
