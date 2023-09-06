package com.ps.recaptcha.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class GoogleRecaptchaResponse {
    @JsonProperty("success")
    private boolean success;

    @JsonProperty("challenge_ts")
    private String challenge_ts;

    @JsonProperty("apk_package_name")
    private String apk_package_name;

    @JsonProperty("error-codes")
    private List<String> errorCodes;
}
