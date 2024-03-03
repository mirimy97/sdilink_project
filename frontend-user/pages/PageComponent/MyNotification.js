import { useEffect, useState } from "react";
import { StyleSheet, Text, View } from "react-native";
import axiosAPI from "../../api/axiosAPI";
import { theme } from "../../colors";
import { Button, TouchableRipple } from "react-native-paper";
import Alarm from "../../component/Alarm";
import { ScrollView } from "react-native-gesture-handler";

export default function MyNotification({ route }) {
  const { cars } = route.params;
  return (
    <View>
      <Text style={{ fontSize: 18, fontWeight: 700, margin: 10 }}>
        알림 내역
      </Text>
      {/* <View style={styles.box}>
        <Text style={styles.title}>🔔  내역</Text>
        <View style={styles.row}>
          <View style={styles.textbox}>
            <Text style={styles.text}>
              <Text style={styles.emp}>삼성화재</Text>에서 차량번호{" "}
              <Text style={styles.emp}>123가2343</Text>1에 대한{"\n"}배터리 정보
              열람 승인 요청을 보냈어요.
            </Text>
            <Text style={styles.date}>2023-05-03 14:47</Text>
          </View>
          <View>
            <Text style={styles.approve}>승인 완료</Text>
          </View>
        </View>
      </View> */}
      <ScrollView>
        <Alarm cars={cars} />
      </ScrollView>
    </View>
  );
}
