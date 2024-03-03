import React, { useEffect, useMemo, useState } from "react";
import { Image, StyleSheet, Text, View } from "react-native";
import { ScrollView } from "react-native-gesture-handler";
import { theme } from "../../colors";
import Module from "../../component/Module";
import { MaterialCommunityIcons } from "@expo/vector-icons";
import { ActivityIndicator, ProgressBar } from "react-native-paper";
import DropDownPicker from "react-native-dropdown-picker";
import axiosAPI from "../../api/axiosAPI";
import HalfPieChart from "../../component/HalfPieChart";
import MonitorCard from "../../component/MonitorCard";
import LineChartMon from "../../component/LineChartMon";
import ProgressCircleComp from "../../component/ProgressCircleComp";

export default function BatteryMon({ navigation }) {
  const [isVisible, setIsVisible] = useState(false);

  const toggleVisibility = () => {
    setIsVisible(!isVisible);
  };

  //헤더 Menu 관련
  const [open, setOpen] = useState(false);
  const [value, setValue] = useState(""); //선택한 값
  const [items, setItems] = useState([]); //cars 값

  //bms 데이터
  const [bms, setBms] = useState({});
  const [cur, setCur] = useState("");

  const [isLoading, setIsLoading] = useState(true);
  const getBmsData = async (car_id) => {
    try {
      // console.log(car_id);
      // 1을 car_id로 바꿔야함.
      const startTime = performance.now();
      setIsLoading(true);
      const res = await axiosAPI.get(`/client/bms/cars/1`);
      const endTime = performance.now();
      const duration = endTime - startTime;
      console.log(res.data);
      console.log(duration);
      setIsLoading(false);
      return res.data;
      // setBms(res.data);
      // setCur(car_id);
      // console.log("22");
    } catch (error) {
      if (error.response && error.response.status === 404) {
        // 404 에러 처리
        console.log("Not Found");
        // 추가적인 로직 또는 에러 처리 방법을 구현할 수 있습니다.
      } else {
        console.log(error);
      }
    }
  };

  const getCars = async () => {
    //내 차 조회
    try {
      const response = await axiosAPI.get("/client/cars", {});

      const itemdata = response.data;
      const cars = itemdata.map((item) => {
        return {
          label: `${item.maker} ${item.modelName} (${item.carNumber})`,
          value: `${item.id}`,
        };
      });
      const res = await getBmsData(cars[0].value);
      setItems(cars);
      setValue(cars[0].value);
      setBms(res.data);
    } catch (error) {
      console.error(error);
    }
  };

  useEffect(() => {
    getCars();
  }, []);

  // if (items.length !== 0) {
  return (
    <ScrollView nestedScrollEnabled={true} style={styles.container}>
      <View style={styles.dropdownPicker}>
        <DropDownPicker
          style={styles.dropdown}
          placeholder="차량을 선택해주세요."
          dropDownContainerStyle={{ borderColor: theme.bg }}
          open={open}
          value={value}
          defaultValue={items[0]}
          items={items}
          setOpen={setOpen}
          setItems={setItems}
          setValue={setValue}
          // onChangeValue={(val) => {
          //   if (value !== cur) {
          //     //중복 호출 방지를 위해 그전 호출값과 비교
          //     res = getBmsData(val);
          //     setBms(res);
          //   }
          // }}
          listMode="SCROLLVIEW"
          mode="SIMPLE"
          textStyle={{ fontWeight: 600 }}
        />
      </View>
      <Text
        style={{
          alignItems: "center",
          textAlign: "center",
          color: theme.grey2,
        }}
      >
        최근 데이터 생성 일시 : {isLoading ? "Loading..." : bms.createdAt}
      </Text>
      <View style={{ ...styles.view, flexDirection: "row" }}>
        <View style={styles.box}>
          <Text style={styles.text}>배터리 종합점수</Text>
          <View style={styles.card}>
            <View style={{ alignItems: "center" }}>
              {isLoading ? (
                <ActivityIndicator size="small" />
              ) : (
                <HalfPieChart btotalScore={bms.btotalScore} />
              )}
            </View>
          </View>
        </View>
        <View style={styles.box}>
          <Text style={styles.text}>배터리 충전량</Text>
          <View style={styles.card}>
            {isLoading ? (
              <ActivityIndicator size="small" />
            ) : (
              <ProgressCircleComp data={isLoading ? "Loading" : bms.soc} />
            )}
          </View>
        </View>
      </View>

      <View style={styles.view}>
        <View style={styles.box}>
          <View
            style={{
              flexDirection: "row",
              alignItems: "flex-end",
            }}
          >
            <Text style={styles.text}>배터리 상세</Text>
            <MaterialCommunityIcons
              name="comment-question-outline"
              size={22}
              color="black"
              style={{ marginLeft: 5, marginBottom: 2 }}
              onPress={toggleVisibility}
            />

            {isVisible && (
              <View style={styles.balloon} visible={false}>
                <Text style={{ fontSize: 9 }}>
                  배터리는 셀 ➝ 모듈 ➝ 팩으로 구성됩니다.{"\n"}모듈의 전압과
                  온도를 바탕으로 이상을 감지합니다.{"\n"}이상 있는 모듈을
                  클릭하여 모듈 내 셀을 확인 가능합니다.
                </Text>
              </View>
            )}
          </View>
          <View style={styles.card}>
            {isLoading ? (
              <ActivityIndicator size="small" />
            ) : (
              <Module navigation={navigation} modules={bms.modules} />
            )}
          </View>
        </View>
      </View>

      <View style={styles.view}>
        <Text style={{ ...styles.text, marginHorizontal: 10 }}>
          BMS모니터링
        </Text>
        <View style={{ flexDirection: "row" }}>
          <View style={styles.box}>
            <MonitorCard
              title="전압"
              data={isLoading ? 0 : Math.round(bms.voltage) + "V"}
              text="350V ~ 390V"
            />
          </View>
          <View style={styles.box}>
            <MonitorCard
              title="전류"
              data={isLoading ? 0 : Math.round(bms.current) + "V"}
              text="0V ~ 100V"
              isLoading={isLoading}
            />
          </View>
          <View style={styles.box}>
            <MonitorCard
              title="온도"
              data={isLoading ? 0 : Math.round(bms.temp) + "℃"}
              text="-15 ℃ ~ +45 ℃"
              isLoading={isLoading}
            />
          </View>
        </View>
      </View>

      <View style={styles.view}>
        <View style={styles.box}>
          <Text style={styles.text}>배터리 충전 정보</Text>
          <View style={styles.row}>
            <Text style={{ color: theme.blue, fontWeight: 600 }}>
              누적 충전량 대비 누적 방전량
            </Text>
            <Text style={{ marginVertical: 4 }}>
              누적 방전량{" "}
              <Text style={{ fontWeight: 600 }}>
                {isLoading ? 0 : bms.totalDischarge}wh
              </Text>{" "}
              / 누적 충전량{" "}
              <Text style={{ fontWeight: 600 }}>
                {isLoading ? 0 : bms.totalCharge}wh
              </Text>
            </Text>
            <ProgressBar
              progress={0.9}
              style={styles.progress}
              color={theme.blue}
            />
            <View style={{ justifyContent: "center", alignItems: "center" }}>
              <Text
                style={{ marginTop: -20, color: theme.white }}
              >{`${Math.round(
                (bms.totalDischarge / bms.totalCharge) * 100
              )}%`}</Text>
            </View>
          </View>
          <View
            style={{
              ...styles.row,
              flexDirection: "row",
            }}
          >
            <View style={{ flexDirection: "row", marginRight: 40 }}>
              <Text
                style={{
                  color: theme.blue,
                  fontWeight: 600,
                  marginRight: 10,
                }}
              >
                급속 충전 횟수
              </Text>
              <Text style={{ fontWeight: 600 }}>{bms.fastCharge}회</Text>
            </View>
            <View style={{ flexDirection: "row" }}>
              <Text
                style={{
                  color: theme.blue,
                  fontWeight: 600,
                  marginRight: 10,
                }}
              >
                동작 시간
              </Text>
              <Text style={{ fontWeight: 600 }}>{bms.totalRuntime}회</Text>
            </View>
          </View>
        </View>
      </View>
      <View style={{ ...styles.view }}>
        <View style={styles.box}>
          <Text style={styles.text}>실시간 전압/전류/온도 그래프</Text>
          <LineChartMon cur={cur} />
        </View>
      </View>
    </ScrollView>
  );

  // } else {
  //   return <Text>Loading...</Text>;
  // }
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
  },
  dropdownPicker: {
    zIndex: 999,
    flex: 1,
    width: 240,
    justifyContent: "center",
    alignSelf: "center",
  },
  dropdown: {
    backgroundColor: "transparent",
    borderColor: theme.bg,
    marginVertical: 10,
    height: 40,
    width: 240,
    fontSize: 20,
  },
  view: {
    flex: 1,
    marginHorizontal: 10,
    marginVertical: 20,
  },
  text: {
    marginBottom: 7,
    fontWeight: 800,
    fontSize: 15,
  },
  box: {
    flex: 1,
    marginHorizontal: 10,
  },
  row: {
    marginBottom: 15,
  },
  card: {
    backgroundColor: theme.white,
    borderRadius: 8,
    // height: 150,
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
  balloon: {
    position: "absolute",
    right: 5,
    bottom: 3,
    alignSelf: "flex-start",
    paddingHorizontal: 10,
    paddingVertical: 5,
    borderRadius: 20,
    backgroundColor: "#e5e5e5",
    borderWidth: 1,
    borderColor: "#ddd",
    marginLeft: 8,
  },
  progress: {
    height: 20,
    borderRadius: 10,
  },
});
