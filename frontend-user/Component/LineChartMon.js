import { View } from "react-native";
import {
  AreaChart,
  Grid,
  LineChart,
  XAxis,
  YAxis,
} from "react-native-svg-charts";
import * as shape from "d3-shape";
import { useEffect, useState } from "react";
import axiosAPI from "../api/axiosAPI";
import { ActivityIndicator, Text } from "react-native-paper";

export default function LineChartMon({ cur }) {
  const [current, setCurrent] = useState([]);
  const [temp, setTemp] = useState([]);
  const [voltage, setVoltage] = useState([]);

  const axesSvg = { fontSize: 10, fill: "grey" };
  const verticalContentInset = { top: 20, bottom: 20 };
  const xAxisHeight = 30;

  //Array of datasets, following this syntax:
  // const data = [
  //   {
  //     data: data1,
  //     svg: { stroke: "purple" },
  //   },
  //   {
  //     data: data2,
  //     svg: { stroke: "green" },
  //   },
  // ];

  useEffect(() => {
    const getGraph = async (cur) => {
      try {
        await axiosAPI.get(`/client/bms/cars/graph/1`, {}).then((res) => {
          const graphdata = res.data;
          graphdata.forEach((graph) => {
            setCurrent((prevCurrent) => [...prevCurrent, graph.current]);
            setTemp((prevTemp) => [...prevTemp, graph.temp]);
            setVoltage((prevVoltage) => [...prevVoltage, graph.voltage]);
          });
        });
      } catch (error) {
        console.error(error);
      }
    };

    getGraph(cur);
  }, []);

  return (
    <>
      <Text> 전압 그래프</Text>
      {voltage ? (
        <View style={{ height: 150, flexDirection: "row" }}>
          <YAxis
            data={voltage}
            contentInset={verticalContentInset}
            svg={{
              fill: "grey",
              fontSize: 10,
            }}
            formatLabel={(value) => `${value}V`}
          />
          <LineChart
            style={{ flex: 1 }}
            data={voltage}
            svg={{ stroke: "rgba(22, 123, 255,1)" }}
            contentInset={{ top: 20, bottom: 20 }}
            curve={shape.curveNatural}
          >
            <Grid
              svg={{
                stroke: "grey",
                strokeOpacity: 0.2,
                strokeWidth: 1,
              }}
            />
          </LineChart>
        </View>
      ) : (
        <ActivityIndicator />
      )}
      <Text>전류 그래프</Text>
      <View style={{ height: 150, flexDirection: "row" }}>
        <YAxis
          data={current}
          contentInset={verticalContentInset}
          svg={{
            fill: "grey",
            fontSize: 10,
          }}
          formatLabel={(value) => `${value}V`}
        />
        <LineChart
          style={{ flex: 1 }}
          data={current}
          svg={{ stroke: "rgba(22, 123, 255,1)" }}
          contentInset={{ top: 20, bottom: 20 }}
          curve={shape.curveNatural}
        >
          <Grid
            svg={{
              stroke: "grey",
              strokeOpacity: 0.2,
              strokeWidth: 1,
            }}
          />
        </LineChart>
      </View>
      <Text>온도 그래프</Text>
      <View style={{ height: 150, flexDirection: "row" }}>
        <YAxis
          data={temp}
          contentInset={verticalContentInset}
          svg={{
            fill: "grey",
            fontSize: 10,
          }}
          formatLabel={(value) => `${value}ºC`}
        />
        <LineChart
          style={{ flex: 1 }}
          data={temp}
          svg={{ stroke: "rgba(22, 123, 255,1)" }}
          contentInset={{ top: 20, bottom: 20 }}
          curve={shape.curveNatural}
        >
          <Grid
            svg={{
              stroke: "grey",
              strokeOpacity: 0.2,
              strokeWidth: 1,
            }}
          />
        </LineChart>
      </View>
    </>
  );
}
