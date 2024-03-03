package com.sdilink.battery.dev.approval.dto;


import com.sdilink.battery.domain.Approval;
import lombok.*;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@ToString
public class ApprovalStatusDto {

    private Long id;
    private int isApprove;


    public ApprovalStatusDto(Approval approval) {
        this.id = approval.getId();
        this.isApprove = approval.getIsApprove();
    }
}
