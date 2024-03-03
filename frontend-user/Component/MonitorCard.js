import { StyleSheet, View } from "react-native";
import { theme } from "../colors";
import { ActivityIndicator, Text } from "react-native-paper";

export default function MonitorCard({ title, data, text, isLoading }) {
  return (
    <View style={{ ...styles.card, alignItems: "center" }}>
      <Text style={styles.title}>{title}</Text>
      <Text style={styles.text}>{text}</Text>
      {isLoading ? (
        <ActivityIndicator />
      ) : (
        <Text style={styles.data}>{data}</Text>
      )}
    </View>
  );
}
const styles = StyleSheet.create({
  card: {
    backgroundColor: theme.white,
    borderRadius: 8,
    // height: 150,
    paddingVertical: 25,
    shadowColor: theme.grey2,
    shadowOffset: {
      width: 0,
      height: 1,
    },
    shadowOpacity: 0.2,
    shadowRadius: 1.41,
    elevation: 2,
  },
  title: {
    fontSize: 15,
    fontWeight: 700,
    color: theme.blue,
  },
  data: {
    marginVertical: 10,
    fontSize: 20,
    fontWeight: 700,
  },
  text: {
    fontSize: 8,
    color: theme.grey2,
    marginVertical: 3,
  },
});
