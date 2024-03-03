import { useNavigation } from "@react-navigation/native";
import { StyleSheet, Text, View } from "react-native";
import { TouchableOpacity } from "react-native-gesture-handler";
import { ActivityIndicator } from "react-native-paper";
import { theme } from "../colors";

export default function Module({ navigation, modules }) {
  if (!modules) {
    return (
      <ActivityIndicator
        color="white"
        style={{ flex: 1, justifyContent: "center" }}
        size="large"
      />
    );
  }
  const squares = modules.map((md, index) => (
    <TouchableOpacity
      key={index}
      style={{
        ...styles.square,
        backgroundColor: md.outlier ? theme.error : theme.blue0,
      }}
      onPress={() => {
        // console.log("click");
        navigation.navigate("CellPage", { md });
      }}
    >
      {/* <Text style={styles.text}>{md.moduleCode}V</Text> */}
      <Text style={{ ...styles.text, fontWeight: 700 }}>{md.moduleCode}V</Text>
      <Text style={styles.text}>{Math.round(md.voltage)}V</Text>
      <Text style={styles.text}>{Math.round(md.temp)}℃</Text>
    </TouchableOpacity>
  ));
  return (
    <View style={styles.container}>
      <View style={styles.flex}>{squares.slice(0, 2)}</View>
      <View style={styles.flex}>{squares.slice(2, 4)}</View>
      <View style={styles.flex}>{squares.slice(4, 6)}</View>
      <View style={styles.flex}>{squares.slice(6, 8)}</View>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
  },
  text: {
    fontSize: 11,
  },
  flex: {
    flex: 1,
    flexDirection: "row",
    justifyContent: "space-evenly",
  },
  square: {
    width: 130,
    height: 75,
    backgroundColor: theme.blue0,
    margin: 3,
    justifyContent: "center",
    alignItems: "center",
    borderRadius: 5,
  },
});
