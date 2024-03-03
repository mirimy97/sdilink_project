package com.sdilink.battery.dev.client.approval.service;


import com.sdilink.battery.dev.approval.dto.ApprovalStatusDto;
import com.sdilink.battery.dev.approval.repository.ApprovalRepository;
import com.sdilink.battery.domain.Approval;
import com.sdilink.battery.domain.Car;
import com.sdilink.battery.exception.common.CustomException;
import com.sdilink.battery.exception.constants.ErrorCode;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;

@Service
@RequiredArgsConstructor
public class ApprovalService {

    private final ApprovalRepository approvalRepository;


//    CarId로 검색
    public List<Approval> findByCarIn(List<Car> carList) {
        return approvalRepository.findByCarIn(carList);
    }



    /* Approval 상태 (is_approve) 변경
    * 0 : 승인대기, 1 : 승인 완료, 2 : 승인거절
    * */
    public ApprovalStatusDto changeStatus(ApprovalStatusDto approvalStatusDto) {

//       request Approval id로 승인 내역 검색
        Long approvalId = approvalStatusDto.getId();
//        데이터 없을 시 예외처리(404)
        Approval approval = approvalRepository.findById(approvalId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Approval record not found with id: " + approvalId ));

//        request 상태코드(승인완료/거절) 유효하지 않을 때 예외처리 (400)
        Integer statusCode = approvalStatusDto.getIsApprove();
        if (!(statusCode == 1 || statusCode == 2)) {
            throw new CustomException(ErrorCode.REQUEST_PARAMETER);
        }

//        상태 (isApprove) 변경 및 저장
        approval.setIsApprove(statusCode);
        approval.setAuthTime();
        approvalRepository.save(approval);

        return new ApprovalStatusDto(approval);
    }
}
