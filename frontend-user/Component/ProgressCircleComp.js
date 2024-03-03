import { View } from "react-native";
import { Text } from "react-native-paper";
import { ProgressCircle } from "react-native-svg-charts";
import { theme } from "../colors";

export default function ProgressCircleComp({ data, type }) {
  // console.log(data);
  return (
    <ProgressCircle
      style={{ height: type == 1 ? 60 : 100 }}
      strokeWidth={8}
      progress={data}
      progressColor={theme.blue}
      animate={true}
    >
      <View style={{ justifyContent: "center" }}>
        <Text style={{ fontSize: 20, color: "#000", alignSelf: "center" }}>
          {data < 1 ? data * 100 : Math.round(data)}%
        </Text>
      </View>
    </ProgressCircle>
  );
}
