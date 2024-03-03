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
@Table(name = "module_log")
public class ModuleLog {

    //    id
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // FK (pack_log)
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "pack_log_id", nullable = false)
    private PackLog packLog;

    //    배터리모듈 일련번호
    @Column(name = "module_code", length = 20, nullable = false)
    private String moduleCode;

    // 전압
    @Column(name = "voltage_m")
    private Float voltageM;

    // 온도
    @Column(name = "temp_m")
    private Float tempM;

    @Column(name = "outlier")
    private Integer outlier;

    // 생성시간 (자동생성X , iot 데이터로 저장함)
    @Column(name = "created_at")
    private LocalDateTime createdAt;


    //    Setter
    public void setOutlier(Integer outlier) {
        this.outlier = outlier;
    }


}
