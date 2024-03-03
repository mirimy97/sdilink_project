import { Image, StyleSheet, View } from "react-native";
import { Text } from "react-native-paper";
import { theme } from "../colors";

const images = {
  image1: require("../assets/images/money.png"),
  image2: require("../assets/images/eco.png"),
  image3: require("../assets/images/tree2.png"),
};

export default function EcoCard({ title, data, image, unit }) {
  return (
    <View style={styles.view}>
      <Text style={styles.title}>{title}</Text>
      <Image style={styles.image} source={images[image]} />
      <Text style={{ color: theme.grey2 }}>
        <Text style={styles.data}>{Math.round(data)}</Text>
        {unit}
      </Text>
    </View>
  );
}
const styles = StyleSheet.create({
  view: {
    marginVertical: 10,
    justifyContent: "center",
    alignItems: "center",
    borderWidth: 1,
    borderColor: theme.grey,
    borderRadius: 10,
    paddingHorizontal: 8,
    paddingVertical: 12,
  },
  title: {
    fontSize: 13,
    fontWeight: 700,
  },
  data: {
    color: theme.blue,
    fontWeight: 700,
    fontSize: 16,
  },
  image: {
    width: 70,
    height: 70,
  },
});
