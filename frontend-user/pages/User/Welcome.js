import { Image, StyleSheet, Text, View } from "react-native";
import { Button } from "react-native-paper";
import { theme } from "../../colors";

export default function Welcome({ navigation }) {
  return (
    <View style={styles.container}>
      <Image
        style={styles.image}
        source={require("../../assets/images/logo2.png")}
      />
      <Text style={styles.text}>
        <Text style={styles.point}>회원가입</Text>이 완료되었습니다.
      </Text>
      <Text>로그인 후 SDLink</Text>
      <Text>기능을 맘껏 누려보세요</Text>
      <Button
        mode="contained"
        style={styles.button}
        onPress={() => navigation.navigate("Login")}
        textColor={theme.white}
        labelStyle={{ fontSize: 15 }}
      >
        로그인 하기
      </Button>
    </View>
  );
}
const styles = StyleSheet.create({
  container: {
    flex: 1,
    alignItems: "center",
    justifyContent: "center",
  },
  point: {
    color: theme.blue,
    fontWeight: 800,
  },
  text: {
    paddingVertical: 20,
    fontSize: 20,
    fontWeight: 600,
  },
  image: {
    height: 100,
    resizeMode: "contain",
  },
  button: {
    marginVertical: 20,
  },
});
