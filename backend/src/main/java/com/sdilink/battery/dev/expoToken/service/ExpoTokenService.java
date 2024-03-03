package com.sdilink.battery.dev.expoToken.service;


import com.sdilink.battery.dev.client.user.repository.UserRepository;
import com.sdilink.battery.dev.expoToken.repository.ExpoTokenRepository;
import com.sdilink.battery.domain.ExpoToken;
import com.sdilink.battery.domain.User;
import com.sdilink.battery.exception.common.CustomException;
import com.sdilink.battery.exception.constants.ErrorCode;
import io.github.jav.exposerversdk.*;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class ExpoTokenService {

    private final ExpoTokenRepository expoTokenRepository;
    private final UserRepository userRepository;

    public String sendExpoPushMessageTest(String recipient, String title, String message) throws PushClientException, InterruptedException {
//        String recipient = "ExponentPushToken[riuA79MbGv5fcm7KCjNI_4]";
//        String title = "제목제목제목제목";
//        String message = "내용내용내용내용내용내용내용내용내용내용";


        // recipient가 올바른 Expo 푸시 토큰인지 확인
        if (!PushClient.isExponentPushToken(recipient))
            throw new Error("Token:" + recipient + " is not a valid token.");

        // ExpoPushMessage 객체 생성
        // 대상, 제목, 내용 설정
        ExpoPushMessage expoPushMessage = new ExpoPushMessage();
        expoPushMessage.getTo().add(recipient);
        expoPushMessage.setTitle(title);
        expoPushMessage.setBody(message);

        // 객체를 요소로 갖는 List를 생성
        List<ExpoPushMessage> expoPushMessages = new ArrayList<>();
        expoPushMessages.add(expoPushMessage);

        // PushClient 객체를 생성합니다.
        PushClient client = new PushClient();
        // ExpoPushMessage 리스트를 조각내어 여러 번에 걸쳐 Expo 푸시 메시지를 보냅니다.
        List<List<ExpoPushMessage>> chunks = client.chunkPushNotifications(expoPushMessages);

        // 메시지 전송 결과를 담을 CompletableFuture<List<ExpoPushTicket>> 리스트를 생성합니다.
        List<CompletableFuture<List<ExpoPushTicket>>> messageRepliesFutures = new ArrayList<>();

        // 각각의 조각을 비동기로 전송하고 CompletableFuture<List<ExpoPushTicket>> 객체를 생성합니다.
        for (List<ExpoPushMessage> chunk : chunks) {
            messageRepliesFutures.add(client.sendPushNotificationsAsync(chunk));
        }

        // Wait for each completable future to finish
        // CompletableFuture<List<ExpoPushTicket>> 객체가 완료될 때까지 대기하며 전송 결과를 받아옵니다.
        List<ExpoPushTicket> allTickets = new ArrayList<>();
        for (CompletableFuture<List<ExpoPushTicket>> messageReplyFuture : messageRepliesFutures) {
            try {
                for (ExpoPushTicket ticket : messageReplyFuture.get()) {
                    allTickets.add(ticket);
                }
            } catch (InterruptedException e) {
                e.printStackTrace();
            } catch (ExecutionException e) {
                e.printStackTrace();
            }
        }

        List<ExpoPushMessageTicketPair<ExpoPushMessage>> zippedMessagesTickets = client.zipMessagesTickets(expoPushMessages, allTickets);

        List<ExpoPushMessageTicketPair<ExpoPushMessage>> okTicketMessages = client.filterAllSuccessfulMessages(zippedMessagesTickets);
        String okTicketMessagesString = okTicketMessages.stream().map(
                p -> "Title: " + p.message.getTitle() + ", Id:" + p.ticket.getId()
        ).collect(Collectors.joining(","));
        System.out.println(
                "Recieved OK ticket for " +
                        okTicketMessages.size() +
                        " messages: " + okTicketMessagesString
        );

        List<ExpoPushMessageTicketPair<ExpoPushMessage>> errorTicketMessages = client.filterAllMessagesWithError(zippedMessagesTickets);
        String errorTicketMessagesString = errorTicketMessages.stream().map(
                p -> "Title: " + p.message.getTitle() + ", Error: " + p.ticket.getDetails().getError()
        ).collect(Collectors.joining(","));
        System.out.println(
                "Recieved ERROR ticket for " +
                        errorTicketMessages.size() +
                        " messages: " +
                        errorTicketMessagesString
        );


        // Countdown 30s
        int wait = 30;
        for (int i = wait; i >= 0; i--) {
            System.out.print("Waiting for " + wait + " seconds. " + i + "s\r");
            Thread.sleep(1000);
        }
        System.out.println("Fetching reciepts...");

        List<String> ticketIds = (client.getTicketIdsFromPairs(okTicketMessages));
        CompletableFuture<List<ExpoPushReceipt>> receiptFutures = client.getPushNotificationReceiptsAsync(ticketIds);

        List<ExpoPushReceipt> receipts = new ArrayList<>();
        try {
            receipts = receiptFutures.get();
        } catch (ExecutionException e) {
            e.printStackTrace();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        System.out.println(
                "Recieved " + receipts.size() + " receipts:");

        for (ExpoPushReceipt reciept : receipts) {
            System.out.println(
                    "Receipt for id: " +
                            reciept.getId() +
                            " had status: " +
                            reciept.getStatus());

        }

        return "Success!";
    }

    public String sendExpoPushMessage(String recipient, String title, String message) throws PushClientException {
//        String recipient = "ExponentPushToken[riuA79MbGv5fcm7KCjNI_4]";
//        String title = "제목제목제목제목";
//        String message = "내용내용내용내용내용내용내용내용내용내용";

        // ExpoPushMessage 객체 생성
        // 대상, 제목, 내용 설정
        ExpoPushMessage expoPushMessage = new ExpoPushMessage();
        expoPushMessage.getTo().add(recipient);
        expoPushMessage.setTitle(title);
        expoPushMessage.setBody(message);

        // 객체를 요소로 갖는 List를 생성
        List<ExpoPushMessage> expoPushMessages = new ArrayList<>();
        expoPushMessages.add(expoPushMessage);

        PushClient client = new PushClient();
        client.sendPushNotificationsAsync(expoPushMessages);

        return "Success!";
    }

    // expo-token 저장 / 업데이트 (임시)
    public ExpoToken saveExpoToken(String accountId, String expoToken) {

        User user = userRepository.findUserByUserId(accountId)
                .orElseThrow(() -> new CustomException(ErrorCode.NO_MATCH_USER));

        ExpoToken existToken = expoTokenRepository.findByUser(user);

        // 토큰 빈 값 보냈을 때
        if (expoToken == null || expoToken.equals("")) {
            throw new CustomException(ErrorCode.REQUEST_PARAMETER);
        }

        if (existToken != null) {
            // 업데이트
            existToken.setToken(expoToken);
            ExpoToken savedToken = expoTokenRepository.save(existToken);

            return savedToken;
        }

        // 생성
        ExpoToken savedToken = expoTokenRepository.save(ExpoToken.builder()
                .user(user)
                .token(expoToken)
                .build());

        return savedToken;
    }

    // user로 expo token 가져오기
    public String getTokenByUser(User user) {

        ExpoToken expoToken = expoTokenRepository.findByUser(user);

        if (expoToken == null) {
            return "no token";
        }

        return expoToken.getToken();
    }
}
