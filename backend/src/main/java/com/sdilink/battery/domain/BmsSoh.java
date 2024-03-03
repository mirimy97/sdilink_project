package com.sdilink.battery.domain;

import lombok.*;
import org.springframework.data.annotation.CreatedDate;

import javax.persistence.*;
import java.time.LocalDateTime;

@Entity
@AllArgsConstructor
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Builder
@ToString
@Getter
@Table(name = "bms_soh")
public class BmsSoh {

    //    id
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    //    FK (User)
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "car_id", nullable = false)
    private Car car;

    //    충방전 사이클
    @Column
    private Integer cycle;

//    예측 SoH
    @Column
    private Float prediction;

    //    생성일시
    @CreatedDate
    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;

    //    기본값 설정
    @PrePersist
    public void prePersist() {
        this.createdAt = LocalDateTime.now();
    }
}
