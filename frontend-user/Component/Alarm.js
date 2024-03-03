import { StyleSheet, Touchable, View } from "react-native";
import { Button, Text, TouchableRipple } from "react-native-paper";
import { theme } from "../colors";
import React, { useEffect, useState } from "react";
import axiosAPI from "../api/axiosAPI";
import { TouchableOpacity } from "react-native-gesture-handler";
import CustomBtn from "./CustomBtn";

export default function Alarm({ cars }) {
  const [history, setHistory] = useState([]);
  const getAlarm = async () => {
    try {
      await axiosAPI.get("/client/histories", {}).then((res) => {
        setHistory(res.data);
      });
      // console.log(items);
    } catch (error) {
      console.error(error);
    }
  };

  useEffect(() => {
    getAlarm();
  }, [history]);

  return (
    <>
      {history.map((his) => {
        const car = cars.find((car) => car.id === his.carId);
        if (his.type == "ViewHistory") {
          //조회이력인지 승인이력인지
          return (
            <View style={styles.box} key={his.id}>
              <Text style={styles.title}>🔎 정보 조회 내역</Text>
              <View style={styles.row}>
                <View style={styles.textbox}>
                  <Text style={styles.text}>
                    <Text style={styles.emp}>{his.insuranceName}</Text>에서
                    차량번호 <Text style={styles.emp}>{car.carNumber}</Text>에
                    대한{"\n"}배터리 정보를 열람했어요.
                  </Text>
                  <Text style={styles.date}>
                    {his.createdAt.replace("T", " ").slice(0, -7)}
                  </Text>
                </View>
              </View>
            </View>
          );
        } else {
          return (
            <View style={styles.box} key={his.id}>
              <Text style={styles.title}>🔔 승인 요청 내역</Text>
              <View style={styles.row}>
                <View style={styles.textbox}>
                  <Text style={styles.text}>
                    <Text style={styles.emp}>{his.insuranceName}</Text>에서
                    차량번호 <Text style={styles.emp}>{car.carNumber}</Text>에
                    대한
                    {"\n"}
                    배터리 정보 열람 을 보냈어요.
                  </Text>
                  <Text style={styles.date}>
                    {his.createdAt.replace("T", " ").slice(0, -7)}
                  </Text>
                  {his.isApprove == 0 ? (
                    <View
                      style={{
                        flexDirection: "row",
                        marginRight: "auto",
                        marginTop: 6,
                      }}
                    >
                      <CustomBtn
                        aid={his.approvalId}
                        isA={2}
                        // onPress={() => handleApprove(his.approvalId, 2)}
                        history={history}
                        setHistory={setHistory}
                        title="열람 거절"
                      />
                      <CustomBtn
                        aid={his.approvalId}
                        isA={1}
                        // onPress={() => handleApprove(his.approvalId, 1)}
                        history={history}
                        setHistory={setHistory}
                        title="열람 승인"
                      />
                    </View>
                  ) : (
                    <></>
                  )}
                </View>
                <View>
                  <Text style={styles.approve}>
                    {his.isApprove === 0
                      ? "승인 대기"
                      : his.isApprove === 1
                      ? "승인 완료"
                      : "승인 거절"}
                  </Text>
                </View>
              </View>
            </View>
          );
        }
      })}
    </>
  );
}

const styles = StyleSheet.create({
  box: {
    backgroundColor: theme.white,
    padding: 10,
    paddingHorizontal: 22,
    borderBottomWidth: 1,
    borderColor: theme.grey,
    borderRadius: 10,
  },
  row: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
  },
  textbox: {
    marginVertical: 5,
  },
  text: {
    fontSize: 13,
  },
  title: {
    color: theme.grey2,
    fontSize: 12,
  },
  emp: {
    color: theme.blue,
    fontWeight: 700,
  },
  date: {
    color: theme.grey2,
    fontSize: 12,
  },
  approve: {
    fontWeight: 700,
    color: theme.grey2,
  },
});
