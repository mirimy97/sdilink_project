import { useNavigate, useParams } from "react-router-dom";
import { useAppDispatch, useAppSelector } from "../redux/hooks";
import { useLocation } from "react-router-dom";
import "./Detail.css";
import { Sidebar } from "../components/DetailTab/Sidebar";
import { useEffect, useState } from "react";
import { BasicInfo } from "../components/DetailTab/BasicInfo";
import { CarDetail } from "../components/DetailTab/CarDetail";
import { BmsInfo } from "../components/DetailTab/BmsInfo";
import { RawData } from "../components/DetailTab/RawData";
import axiosApi from "../axiosApi";
import {
  AnalysisInfo,
  BMSChartData,
  CarBasicInfo,
  ModuleCellsMapping,
  NowBMSData,
  SOHData,
  UserDetailInfo,
} from "../interfaces";
import { carDetailInfo } from "../redux/detail";
import { logoutIns } from "../redux/insurance";

export function Detail() {
  const carId = useParams().carId;
  const location = useLocation();
  const userName = location.state.userName;
  const approvalId = location.state.approvalId;
  const accessToken = useAppSelector((store) => store.insurance.token);
  // console.log(carId);
  const [loading, setLoading] = useState(true);
  const [basicInfo, setBasicInfo] = useState<CarBasicInfo | null>(null);
  const [userDetailInfo, setUserDetailInfo] = useState<UserDetailInfo | null>(
    null
  );
  const [analysisInfo, setAnalysisInfo] = useState<AnalysisInfo | null>(null);
  const [moduleCellMapping, setModuleCellMapping] =
    useState<ModuleCellsMapping | null>(null);

  const [nowBMSData, setNowBMSData] = useState<NowBMSData[] | null>(null);
  const [bmsGraphData, setBMSGraphData] = useState<BMSChartData[] | null>(null);

  const dispatch = useAppDispatch();
  const navigate = useNavigate();

  // 현재 시각
  // default 날짜 계산
  const today = new Date();
  const endYear = today.getFullYear();
  const endMonth = ("0" + (today.getMonth() + 1)).slice(-2);
  const endDay = ("0" + today.getDate()).slice(-2);
  const hours = ("0" + today.getHours()).slice(-2);
  const minutes = ("0" + today.getMinutes()).slice(-2);
  const timeString = hours + ":" + minutes;
  const EndDateString = endYear + "-" + endMonth + "-" + endDay;
  const [nowTime, setNowTime] = useState<string | null>(null);
  const [SOHData, setSOHData] = useState<SOHData[] | null>(null);
  const [err, setErr] = useState<number | null>(null);

  useEffect(() => {
    // 차종 기본정보
    axiosApi
      .get(`/insurance/carinfos/cars/${carId}`, {
        headers: {
          Authorization: accessToken,
        },
      })
      .then((res) => setBasicInfo(res.data))
      .catch((err) => {
        console.log(err);
        if (err.response.status === 403) {
          dispatch(logoutIns());
          navigate("/login");
        }
      });
    // 개인 정보 + 차량 기본 정보
    axiosApi
      .get(`/insurance/approvals/${approvalId}/detail`, {
        headers: {
          Authorization: accessToken,
        },
      })
      .then((res) => {
        // console.log(res.data);
        setUserDetailInfo(res.data);
        dispatch(carDetailInfo(res.data));
      })
      .catch((err) => setErr(err.response.data.status));
    // 고객 차량 분석, 예측 정보 조회
    axiosApi
      .get(`/insurance/approvals/${approvalId}/analysis`, {
        headers: {
          Authorization: accessToken,
        },
      })
      .then((res) => {
        // console.log(res.data);
        setAnalysisInfo(res.data);
      })
      .catch((err) => setErr(err.response.data.status));
    // 모듈 - 셀 매핑 데이터
    axiosApi
      .get(`/insurance/approvals/${approvalId}/bms/codes`, {
        headers: {
          Authorization: accessToken,
        },
      })
      .then((res) => {
        // console.log(res.data);
        setModuleCellMapping(res.data);
      })
      .catch((err) => setErr(err.response.data.status));

    // soh 차트 데이터
    axiosApi
      .get(`insurance/approvals/${approvalId}/bms/sohgraph`, {
        headers: {
          Authorization: accessToken,
        },
      })
      .then((res) => setSOHData(res.data))
      .then(() => setLoading(false))
      .catch((err) => console.log(err));

    // bms 전압, 전류, 온도 차트 데이터
    axiosApi
      .get(`/insurance/approvals/${approvalId}/bms/graph`, {
        headers: {
          Authorization: accessToken,
        },
      })
      .then((res) => {
        // console.log(res.data);
        setBMSGraphData(res.data);
        setNowTime(res.data[179].name);

        return axiosApi.get(`insurance/approvals/${approvalId}/bms`, {
          headers: {
            Authorization: accessToken,
          },
          params: {
            time: res.data[179].name + ":00",
          },
        });
      })
      .then((res) => {
        // console.log(res.data);
        setNowBMSData(res.data);
      })
      .catch((err) => console.log(err));
  }, []);

  useEffect(() => {
    if (basicInfo) {
      setLoading(false);
    }
  }, [basicInfo]);

  const [sideState, setSideState] = useState<number>(1);

  return loading ? (
    <></>
  ) : (
    <div style={{ height: "100%", marginLeft: "5%", marginRight: "-8%" }}>
      <Sidebar sideState={sideState} setSideState={setSideState} />
      <div style={{ height: "100%" }}>
        <div style={{ paddingTop: "25px", marginBottom: "30px" }}>
          <span
            style={{ fontWeight: "bold", fontSize: "20px", color: "#167BFF" }}
          >
            {userName}
          </span>
          <span
            style={{ fontWeight: "bold", fontSize: "20px", color: "#bbbbbb" }}
          >
            님 상세 정보
          </span>
        </div>

        {sideState === 1 ? (
          <BasicInfo basicInfo={basicInfo} />
        ) : sideState === 2 ? (
          <CarDetail
            userDetailInfo={userDetailInfo}
            analysisInfo={analysisInfo}
            SOHData={SOHData}
            err={err}
          />
        ) : sideState === 3 ? (
          <BmsInfo
            nowBMSData={nowBMSData}
            setNowBMSData={setNowBMSData}
            approvalId={approvalId}
            accessToken={accessToken}
            nowTime={nowTime}
            setNowTime={setNowTime}
            bmsGraphData={bmsGraphData}
          />
        ) : (
          <RawData
            userDetailInfo={userDetailInfo}
            moduleCellMapping={moduleCellMapping}
            nowTime={nowTime}
            err={err}
          />
        )}
      </div>
    </div>
  );
}
