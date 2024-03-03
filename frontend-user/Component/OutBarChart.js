import { useEffect, useState } from "react";
import { View } from "react-native";
import { Text } from "react-native-paper";
import { LinearGradient } from "react-native-svg";
import { Stop } from "react-native-svg";
import { Defs } from "react-native-svg";
import { BarChart, Grid, XAxis, YAxis } from "react-native-svg-charts";

export default function OutBarChart({ graph, onMaxValueChange }) {
  const fill = "rgb(134, 65, 244)";
  // console.log(graph);
  const [labels, setLabels] = useState([]);
  const [data, setData] = useState([]);
  useEffect(() => {
    if (graph) {
      const newLabels = graph.map((g) => g.code);
      setLabels(newLabels);
      const newData = graph.map((g) => g.count);
      setData(newData);

      const maxValue = Math.max(...newData);
      const maxLabel =
        newLabels[newData.findIndex((value) => value === maxValue)];
      onMaxValueChange(maxValue, maxLabel);
    }
  }, [graph, onMaxValueChange]);
  console.log(labels);

  const Gradient = () => (
    <Defs key={"gradient"}>
      <LinearGradient id={"gradient"} x1={"0%"} y={"0%"} x2={"0%"} y2={"100%"}>
        <Stop offset={"0%"} stopColor={"rgb(134, 65, 244)"} />
        <Stop offset={"100%"} stopColor={"rgb(22, 123, 255)"} />
      </LinearGradient>
    </Defs>
  );
  return (
    <View style={{ height: 250, flexDirection: "column", marginTop: 20 }}>
      <View style={{ height: 250, flexDirection: "row" }}>
        <YAxis
          data={data}
          contentInset={{ top: 32, bottom: 10 }}
          svg={{
            fill: "grey",
            fontSize: 9,
          }}
          formatLabel={(value) => `${value}`}
        />
        <BarChart
          style={{ flex: 1 }}
          data={data}
          svg={{
            strokeWidth: 2,
            fill: "url(#gradient)",
          }}
          contentInset={{ top: 30, bottom: 5 }}
        >
          <Grid
            svg={{
              stroke: "grey",
              strokeOpacity: 0.2,
              strokeWidth: 1,
            }}
          />
          <Gradient />
        </BarChart>
      </View>

      <XAxis
        style={{ marginHorizontal: 0 }}
        data={data}
        formatLabel={(value, index) => labels[index]}
        contentInset={{ left: 30, right: 20 }}
        svg={{ fontSize: 5, fill: "grey" }}
      />
    </View>
  );
}
