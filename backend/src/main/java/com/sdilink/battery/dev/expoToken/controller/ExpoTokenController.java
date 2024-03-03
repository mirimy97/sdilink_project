package com.sdilink.battery.dev.expoToken.controller;


import com.sdilink.battery.dev.expoToken.service.ExpoTokenService;
import io.github.jav.exposerversdk.PushClientException;
import io.swagger.annotations.Api;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/client/expo")
public class ExpoTokenController {

    private final ExpoTokenService expoTokenService;


    // 푸시 알림 테스트
    @GetMapping("")
    public ResponseEntity<?> sendExpoPushMessage() throws PushClientException, InterruptedException {

        String recipient = "ExponentPushToken[riuA79MbGv5fcm7KCjNI_4]";
        String title = "제목제목제목제목";
        String message = "내용내용내용내용내용내용내용내용내용내용";
        String sended = expoTokenService.sendExpoPushMessage(recipient, title, message);

        return ResponseEntity.ok(sended);
    }
}
