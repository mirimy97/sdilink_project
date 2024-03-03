import { View } from "react-native";
import { Text } from "react-native-svg";
import { PieChart } from "react-native-svg-charts";
export default function HalfPieChart({ btotalScore }) {
  const data = [
    {
      key: 1,
      value: 60,
      svg: { fill: "#E74C3C" },
    },
    {
      key: 2,
      value: 60,
      svg: { fill: "#FFA42E" },
    },
    {
      key: 3,
      value: 60,
      svg: { fill: "#2ECC71" },
    },
  ];

  return (
    <PieChart
      style={{ height: 100, width: 120 }}
      data={data}
      startAngle={-Math.PI * 0.5}
      endAngle={Math.PI * 0.5}
      //   padAngle={0}
      innerRadius="92%"
    >
      <Text textAnchor="middle" x="-10" fontSize={24} fill="#000">
        {Math.round(btotalScore)}점
        {/* {isNaN(Math.round(btotalScore)) ? "" : `${Math.round(btotalScore)}점`} */}
      </Text>
      <Text textAnchor="middle" x="-1" y="22" fontSize={9} fill="#000">
        충전량을 25~75%로 유지하면
      </Text>
      <Text textAnchor="middle" x="-1" y="32" fontSize={9} fill="#000">
        성능을 오래 유지할 수 있습니다.
      </Text>
    </PieChart>
  );
}
