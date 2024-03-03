import { useState } from "react";
import { StyleSheet, View } from "react-native";
import { Button, Text } from "react-native-paper";
import { theme } from "../colors";
import { FontAwesome5 } from "@expo/vector-icons";
import { FontAwesome } from "@expo/vector-icons";

export default function ChargingBox({ searchOption }) {
  const [checkedTypes, setCheckedTypes] = useState([]);
  const [checkedCharge, setCheckedCharge] = useState([]);

  const handleCheckboxChange = (value) => {
    console.log(value);
    const index = checkedTypes.indexOf(value);
    if (index >= 0) {
      setCheckedTypes([
        ...checkedTypes.slice(0, index),
        ...checkedTypes.slice(index + 1),
      ]);
    } else {
      setCheckedTypes([...checkedTypes, value]);
    }
  };

  const handleCheckboxChange2 = (value) => {
    setCheckedCharge([value]);
  };

  const handleSearch = () => {
    searchOption(checkedTypes, checkedCharge);
  };
  return (
    <View style={styles.optionsBox}>
      <View style={styles.optionBox}>
        <View style={styles.optionTitle}>
          <FontAwesome5 name="charging-station" size={18} color="black" />
          <Text style={styles.optionText}>충전기 타입</Text>
        </View>

        <View style={styles.chargeType}>
          <Button
            onPress={() => handleCheckboxChange("DC차데모")}
            style={
              checkedTypes.includes("DC차데모")
                ? { ...styles.checked, labelStyle: { color: theme.white } }
                : styles.unchecked
            }
            labelStyle={
              checkedTypes.includes("DC차데모")
                ? { color: theme.white }
                : { color: theme.black }
            }
          >
            DC차데모
          </Button>
          <Button
            onPress={() => handleCheckboxChange("DC콤보")}
            style={
              checkedTypes.includes("DC콤보")
                ? { ...styles.checked, labelStyle: { color: theme.white } }
                : styles.unchecked
            }
            labelStyle={
              checkedTypes.includes("DC콤보")
                ? { color: theme.white }
                : { color: theme.black }
            }
          >
            DC콤보
          </Button>
          <Button
            style={
              checkedTypes.includes("AC완속")
                ? styles.checked
                : styles.unchecked
            }
            onPress={() => handleCheckboxChange("AC완속")}
            labelStyle={
              checkedTypes.includes("AC완속")
                ? { color: theme.white }
                : { color: theme.black }
            }
          >
            AC완속
          </Button>
          <Button
            style={
              checkedTypes.includes("AC3상") ? styles.checked : styles.unchecked
            }
            onPress={() => handleCheckboxChange("AC3상")}
            labelStyle={
              checkedTypes.includes("AC3상")
                ? { color: theme.white }
                : { color: theme.black }
            }
          >
            AC3상
          </Button>
        </View>
      </View>

      <View style={styles.optionBox}>
        <View style={styles.optionTitle}>
          <FontAwesome name="won" size={18} color="black" />
          <Text style={styles.optionText}>주차요금</Text>
        </View>
        <View style={styles.chargeType}>
          <Button
            onPress={() => handleCheckboxChange2("checkbox1")}
            style={
              checkedCharge.includes("checkbox1")
                ? styles.checked
                : styles.unchecked
            }
            labelStyle={
              checkedCharge.includes("checkbox1")
                ? { color: theme.white }
                : { color: theme.black }
            }
          >
            전체
          </Button>
          <Button
            onPress={() => handleCheckboxChange2("checkbox2")}
            style={
              checkedCharge.includes("checkbox2")
                ? styles.checked
                : styles.unchecked
            }
            labelStyle={
              checkedCharge.includes("checkbox2")
                ? { color: theme.white }
                : { color: theme.black }
            }
          >
            무료
          </Button>
          <Button
            style={
              checkedCharge.includes("checkbox3")
                ? styles.checked
                : styles.unchecked
            }
            onPress={() => handleCheckboxChange2("checkbox3")}
            labelStyle={
              checkedCharge.includes("checkbox3")
                ? { color: theme.white }
                : { color: theme.black }
            }
          >
            유료
          </Button>
        </View>
      </View>
      <Button
        style={styles.button}
        textColor={theme.blue}
        onPress={handleSearch}
      >
        검색
      </Button>
    </View>
  );
}
const styles = StyleSheet.create({
  optionsBox: {
    backgroundColor: theme.white,
    position: "absolute",
    top: 33,
    width: "100%",
    height: 280,
    zIndex: 10,
  },
  optionBox: {
    marginVertical: 16,
  },
  optionTitle: {
    flexDirection: "row",
    alignItems: "center",
    marginHorizontal: 10,
  },
  optionText: {
    fontSize: 16,
    fontWeight: "bold",
    marginVertical: 10,
    marginLeft: 3,
  },
  chargeType: {
    flexDirection: "row",
    marginHorizontal: 10,
  },
  checked: {
    backgroundColor: theme.blue,
    width: 85,
    height: 38,
    marginRight: 3,
  },
  unchecked: {
    backgroundColor: theme.blue0,
    width: 85,
    height: 38,
    marginRight: 3,
  },
  button: {
    width: 100,
    marginLeft: "auto",
    marginTop: "auto",
    marginBottom: 14,
    marginRight: 14,
    borderWidth: 1,
    borderColor: theme.blue,
  },
});
