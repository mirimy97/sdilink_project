package com.sdilink.battery.dev.viewHistory.dto;


import com.sdilink.battery.domain.Approval;
import com.sdilink.battery.domain.Insurance;
import com.sdilink.battery.domain.ViewHistory;
import lombok.*;

import java.time.LocalDateTime;

@NoArgsConstructor
@Getter
@Setter
@ToString
public class TotalHistoryDto {

    private Long id;
    private Long insuranceId;
    private String insuranceName;
    private Long carId;
    private String carNumber;
    private String type;
    private Long approvalId;    // 승인내역 일 때
    private Integer isApprove;   // 승인내역 일 때
    private LocalDateTime createdAt;

//    ViewHistory 객체로 생성 시 (type = ViewHistory)
    public TotalHistoryDto(ViewHistory viewHistory) {
        this.id = viewHistory.getId();
        this.insuranceId = viewHistory.getInsurance().getId();
        this.insuranceName = viewHistory.getInsurance().getName();
        this.carId = viewHistory.getCar().getId();
        this.carNumber = viewHistory.getCar().getCarNumber();
        this.type = "ViewHistory";
        this.approvalId = null;
        this.isApprove = -1;
        this.createdAt = viewHistory.getCreatedAt();
    }

//    Approval 객체로 생성 시 (type = Approval)
    public TotalHistoryDto(Approval approval) {
        this.id = approval.getId();
        this.insuranceId = approval.getInsurance().getId();
        this.insuranceName = approval.getInsurance().getName();
        this.carId = approval.getCar().getId();
        this.carNumber = approval.getCar().getCarNumber();
        this.type = "Approval";
        this.approvalId = approval.getId();
        this.isApprove = approval.getIsApprove();
        this.createdAt = approval.getCreatedAt();
    }

}
