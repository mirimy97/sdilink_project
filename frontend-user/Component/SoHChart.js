import { View } from "react-native";
import { Grid, LineChart, XAxis, YAxis } from "react-native-svg-charts";
import * as shape from "d3-shape";
import { Line } from "react-native-svg";
import { Text } from "react-native-svg";
import { Path } from "react-native-svg";
import { Defs } from "react-native-svg";
import { LinearGradient } from "react-native-svg";
import { Stop } from "react-native-svg";
import { useState } from "react";
import axiosAPI from "../api/axiosAPI";

export default function SoHChart() {
  const [data, setData] = useState([]);
  const axesSvg = {
    fontSize: 10,
    fill: "grey",
    fontWeight: "bold",
  };

  //Array of datasets, following this syntax:

  const HorizontalLine = ({ y }) => (
    <Line
      key={"zero-axis"}
      x1={"0%"}
      x2={"100%"}
      y1={y(75)}
      y2={y(75)}
      stroke={"grey"}
      strokeDasharray={[4, 8]}
      strokeWidth={2}
    />
  );
  useState(() => {
    const getSoH = async (car_id) => {
      try {
        // console.log(car_id);
        // 1을 car_id로 바꿔야함.
        await axiosAPI.get(`/client/bms/cars/1/graph/soh`, {}).then((res) => {
          console.log(res.data);
          const newData = res.data.map((d) => d.SOH * 100);
          setData(newData);
        });
      } catch (error) {
        console.error(error);
      }
    };
    getSoH();
  }, []);

  const Gradient = () => (
    <Defs key={"gradient"}>
      <LinearGradient id={"gradient"} x1={"0"} y={"0%"} x2={"100%"} y2={"0%"}>
        <Stop offset={"0%"} stopColor={"rgb(134, 65, 244)"} />
        <Stop offset={"100%"} stopColor={"rgb(22, 123, 255)"} />
      </LinearGradient>
    </Defs>
  );
  return (
    <View style={{ height: 200, flexDirection: "row" }}>
      <YAxis
        data={data}
        contentInset={{ top: 20, bottom: 20, left: 10, right: 100 }}
        svg={axesSvg}
        min={75}
      />
      <LineChart
        style={{ flex: 1 }}
        data={data}
        svg={{
          strokeWidth: 2,
          stroke: "url(#gradient)",
        }}
        contentInset={{ top: 20, bottom: 20 }}
        curve={shape.curveNatural}
        yAccessor={({ item }) => item}
        xAccessor={({ index }) => index}
      >
        {/* <Shadow yAccessor={({ item }) => item} /> */}
        {/* <DashedLine /> */}
        <Grid
          svg={{
            stroke: "grey",
            strokeOpacity: 0.2,
            strokeWidth: 1,
          }}
        />
        <Gradient />
        <HorizontalLine />
      </LineChart>
    </View>
  );
}
