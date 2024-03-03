import React, { useEffect, useState } from "react";
import { View } from "react-native";
import { ScrollView, StyleSheet, Text } from "react-native";
import { theme } from "../../colors";
// import OutBarChart from "../../component/OutBarChart";
import ProgressCircleComp from "../../component/ProgressCircleComp";
import SoHChart from "../../component/SoHChart";
import OutBarChart from "../../component/OutBarChart";
import axiosAPI from "../../api/axiosAPI";
export default function BatteryPre() {
  const [ai, setAI] = useState([]);
  useEffect(() => {
    const getAI = async () => {
      try {
        await axiosAPI.get("/client/bms/cars/1/ai", {}).then((res) => {
          console.log(res.data);
          setAI(res.data);
        });
        // console.log(items);
      } catch (error) {
        console.error(error);
      }
    };
    getAI();
  }, []);

  const [maxValue, setMaxValue] = useState(null);
  const [maxLabel, setMaxLabel] = useState(null);

  const handleMaxValueChange = (value, label) => {
    setMaxValue(value);
    setMaxLabel(label);
    // 원하는 대로 가장 큰 값과 레이블을 처리합니다.
  };
  return (
    <ScrollView style={styles.container}>
      <View style={styles.view}>
        <View style={styles.box}>
          <Text style={styles.text}>예상 주행 가능 거리</Text>
          <Text style={styles.text2}>
            ‘ 현재 배터리 잔량(SoC) + 전비 + 배터리 노후도(SoH) ’를 기반으로
            주행 가능 거리를 예측한 결과입니다.
          </Text>
          <View
            style={{
              ...styles.card,
              paddingHorizontal: 30,
              flexDirection: "row",
              justifyContent: "space-between",
              alignItems: "center",
            }}
          >
            <Text>총 주행 가능 거리</Text>
            <Text style={{ fontSize: 25, color: theme.blue, fontWeight: 700 }}>
              {isNaN(ai.driveDistance) ? "" : `${ai.driveDistance}KM`}
            </Text>
          </View>
        </View>
      </View>

      <View style={styles.view}>
        <View style={styles.box}>
          <Text style={styles.text}>SoH(배터리 상태) 예측 모델</Text>
          <View style={styles.card}>
            <View
              style={{
                flexDirection: "row",
                justifyContent: "space-between",
                alignItems: "center",
                paddingHorizontal: 10,
              }}
            >
              <View
                style={{
                  width: 60,
                  marginRight: 20,
                }}
              >
                <ProgressCircleComp
                  data={ai.soh && ai.soh.toFixed(2)}
                  type={1}
                />
              </View>
              <View style={{ width: 200 }}>
                <Text style={styles.plain}>
                  현재 배터리 성능 상태는{" "}
                  <Text style={styles.emp}>
                    {isNaN(ai.soh) ? "" : `${Math.round(ai.soh * 100)}`}%
                  </Text>{" "}
                  입니다.{"\n"}
                  완충 기준으로{" "}
                  <Text style={styles.emp}>
                    {isNaN(ai.leftCycle) ? "" : `${ai.leftCycle}`}번
                  </Text>{" "}
                  충전할 수 있습니다.
                </Text>
              </View>
            </View>
            <View>
              <SoHChart />
            </View>
          </View>
        </View>
      </View>

      <View style={styles.view}>
        <View style={styles.box}>
          <Text style={styles.text}>이상치 데이터 분석</Text>
          <View
            style={{
              ...styles.card,
            }}
          >
            <View
              style={{
                flexDirection: "row",
                justifyContent: "space-between",
                alignItems: "center",
                paddingHorizontal: 10,
              }}
            >
              <Text style={{ ...styles.plain, width: 80 }}>
                <Text
                  style={{ color: theme.error, fontWeight: 700, fontSize: 30 }}
                >
                  {maxValue}
                </Text>
                건
              </Text>
              <Text
                style={{
                  ...styles.plain,
                  width: 200,
                }}
              >
                오염도 <Text style={styles.emp}>0.01%</Text>기준으로 가장 많은
                이상치가{"\n"}감지된 배터리 셀은{" "}
                <Text style={styles.emp}> {maxLabel}</Text> 입니다.
              </Text>
            </View>
            <View>
              <OutBarChart
                graph={ai.outlierGraph}
                onMaxValueChange={handleMaxValueChange}
              />
            </View>
          </View>
        </View>
      </View>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
  },
  view: {
    flex: 1,
    marginHorizontal: 10,
    marginVertical: 20,
  },
  text: {
    fontWeight: 800,
    fontSize: 15,
    marginVertical: 8,
  },
  text2: {
    marginBottom: 10,
    fontSize: 12,
  },
  box: {
    flex: 1,
    marginHorizontal: 10,
  },
  card: {
    backgroundColor: theme.white,
    borderRadius: 8,
    paddingVertical: 25,
    paddingHorizontal: 25,
    shadowColor: theme.grey2,
    shadowOffset: {
      width: 0,
      height: 1,
    },
    shadowOpacity: 0.2,
    shadowRadius: 1.41,
    elevation: 2,
  },
  padding: {
    flexDirection: "row",
  },
  plain: {
    fontSize: 11,
  },
  emp: {
    fontSize: 12,
    color: theme.blue,
    fontWeight: 700,
  },
});
