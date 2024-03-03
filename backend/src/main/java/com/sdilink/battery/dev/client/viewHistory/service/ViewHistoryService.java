package com.sdilink.battery.dev.client.viewHistory.service;


import com.sdilink.battery.dev.viewHistory.repository.ViewHistoryRepository;
import com.sdilink.battery.domain.Car;
import com.sdilink.battery.domain.ViewHistory;
import lombok.RequiredArgsConstructor;

import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class ViewHistoryService {

    private final ViewHistoryRepository viewHistoryRepository;

    public List<ViewHistory> findByCarIn(List<Car> carList) {
        return viewHistoryRepository.findByCarIn(carList);
    }

}
