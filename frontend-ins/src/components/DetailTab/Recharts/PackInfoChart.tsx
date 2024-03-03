import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import { PackInfoChartTitle } from "./PackInfoChartTitle";
import { BMSChartData, NowBMSData } from "../../../interfaces";
import axiosApi from "../../../axiosApi";

export function PackInfoChart({
  setNowBMSData,
  approvalId,
  accessToken,
  setNowTime,
  bmsGraphData,
}: {
  setNowBMSData: (data: NowBMSData[]) => void;
  approvalId: string;
  accessToken: string;
  setNowTime: (t: string) => void;
  bmsGraphData: BMSChartData[] | null;
}) {
  const handleClick = (data: any) => {
    if (data && data.activePayload && data.activePayload.length) {
      const selectedData = data.activePayload[0].payload;
      // setSelectedX(selectedData.name);
      // console.log(selectedData.name);
      // axios 요청 (연동)
      axiosApi
        .get(`/insurance/approvals/${approvalId}/bms`, {
          headers: {
            Authorization: accessToken,
          },
          params: {
            time: selectedData.name + ":00", // 임시 데이터 (selectedData.name이 들어가야함)
          },
        })
        .then((res) => {
          // console.log(res.data);
          setNowBMSData(res.data);
          setNowTime(selectedData.name);
        })
        .catch((err) => console.log(err));
    } else {
      // setSelectedX(null);
      console.log("없음");
    }
  };

  return (
    <div style={{ width: "100%" }}>
      <PackInfoChartTitle />
      <ResponsiveContainer width="100%" height={200}>
        <LineChart
          data={bmsGraphData!}
          syncId="BMSpack"
          margin={{
            top: 10,
            right: 30,
            left: 0,
            bottom: 30,
          }}
          onClick={handleClick}
        >
          {/* <CartesianGrid strokeDasharray="3 3" stroke="#ccc" />/ */}
          <XAxis
            dataKey="name"
            label={{ value: "전압 (V)", position: "insideBottomRight" }}
            tick={{ display: "none" }}
          />
          <YAxis domain={[350, 390]} />
          <Tooltip />
          <Line
            type="monotone"
            dataKey="voltageP"
            stroke="#167BFF"
            fill="#167BFF"
            dot={false}
          />
        </LineChart>
      </ResponsiveContainer>
      <ResponsiveContainer width="100%" height={200}>
        <LineChart
          data={bmsGraphData!}
          syncId="BMSpack"
          margin={{
            top: 10,
            right: 30,
            left: 0,
            bottom: 30,
          }}
          onClick={handleClick}
        >
          {/* <CartesianGrid strokeDasharray="3 3" /> */}
          <XAxis
            dataKey="name"
            label={{ value: "전류 (A)", position: "insideBottomRight" }}
            tick={{ display: "none" }}
          />
          <YAxis domain={[0, 150]} />
          <Tooltip />
          <Line
            type="monotone"
            dataKey="current"
            stroke="#167BFF"
            fill="#167BFF"
            dot={false}
          />
        </LineChart>
      </ResponsiveContainer>
      <ResponsiveContainer width="100%" height={200}>
        <LineChart
          data={bmsGraphData!}
          syncId="BMSpack"
          margin={{
            top: 10,
            right: 30,
            left: 0,
            bottom: 20,
          }}
          onClick={handleClick}
        >
          {/* <CartesianGrid strokeDasharray="3 3" /> */}
          <XAxis
            dataKey="name"
            label={{ value: "온도 (℃)", position: "insideBottomRight" }}
            tick={{ display: "none" }}
          />
          <YAxis domain={[10, 50]} />
          <Tooltip />
          <Line
            type="monotone"
            dataKey="tempP"
            stroke="#167BFF"
            fill="#167BFF"
            dot={false}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
