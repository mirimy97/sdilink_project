import { StyleSheet, View, Text } from "react-native";
import { theme } from "../colors";
import { EvilIcons } from "@expo/vector-icons";
export default function MarkerInfoBox({ markerInfo }) {
  console.log(markerInfo);
  const bat = {
    1: "DC차데모",
    2: "AC완속",
    3: "DC차데모+AC3상",
    4: "DC콤보",
    5: "DC차데모+DC콤보",
    6: "DC차데모+AC3상+DC콤보",
    7: "AC3상",
  };
  const stat = {
    1: "통신이상",
    2: "충전대기",
    3: "충전중",
    4: "운영중지",
    5: "점검중",
    9: "상태 미확인",
  };
  return (
    <View style={styles.optionBox}>
      <Text style={styles.statNm}>{markerInfo.statNm}</Text>
      <Text style={styles.busiNm}>{markerInfo.busiNm}</Text>
      <View style={styles.addr}>
        <EvilIcons name="location" size={22} color={theme.grey2} />
        <Text style={{ color: theme.grey2 }}>{markerInfo.addr}</Text>
      </View>
      <View style={{ flexDirection: "row" }}>
        <View style={styles.textBox}>
          {markerInfo.chgerType && (
            <Text>{bat[markerInfo.chgerType.replace(/^0+/, "")]}</Text>
          )}
          {/* .replace(/^0+/, "") */}
        </View>
        <View style={styles.textBox}>
          <Text>
            {markerInfo.parkingFree === "Y"
              ? "주차 유료"
              : markerInfo.parkingFee === "N"
              ? "주차 무료"
              : "주차료 확인불가"}
          </Text>
        </View>
        <View style={styles.textBox}>
          <Text>{stat[markerInfo.stat]}</Text>
        </View>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  optionBox: {
    flex: 1,
    backgroundColor: theme.white,
    borderTopLeftRadius: 20,
    borderTopRightRadius: 20,
    shadowColor: theme.grey2,
    shadowOffset: { width: 0, height: -3 },
    shadowOpacity: 0.1,
    shadowRadius: 3,
    elevation: 5,
    justifyContent: "center",
    paddingHorizontal: 14,
  },
  statNm: {
    color: theme.blue,
    fontWeight: 800,
    fontSize: 16,
    paddingVertical: 10,
  },
  busiNm: {
    paddingBottom: 8,
  },
  addr: {
    paddingBottom: 10,
    alignItems: "center",
    flexDirection: "row",
  },
  textBox: {
    backgroundColor: "#E1F0DA",
    padding: 5,
    borderRadius: 10,
    alignItems: "center",
    marginRight: 5,
  },
});
