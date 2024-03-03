package com.sdilink.battery.domain;


import lombok.*;

import javax.persistence.*;
import java.time.LocalDateTime;

@Entity
@AllArgsConstructor
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Builder
@ToString
@Getter
@Table(name = "cell_log")
public class CellLog {

    //    id
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // FK (module_log)
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "module_log_id", nullable = false)
    private ModuleLog moduleLog;

    //    배터리셀 일련번호
    @Column(name = "cell_code", length = 20, nullable = false)
    private String cellCode;

    // 전압
    @Column(name = "voltage_c")
    private Float voltageC;

//  이상치 점수
    @Column
    private Float outlier;

//    정상 여부 (1 : 정상, -1 : 비정상)
    @Column(name = "is_normal")
    private Integer isNormal;

    // 생성시간 (자동생성X , iot 데이터로 저장함)
    @Column(name = "created_at")
    private LocalDateTime createdAt;
}
