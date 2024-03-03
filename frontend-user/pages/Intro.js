import { Text, Image, StyleSheet, View } from "react-native";
import { TouchableOpacity } from "react-native-gesture-handler";
import { Button } from "react-native-paper";
import { theme } from "../colors";
export default function Intro({ navigation }) {
  return (
    <View style={styles.container}>
      <View style={styles.left}>
        <Text style={styles.text}>
          <Text style={styles.textBold}>내 차를 등록</Text>하고 {"\n"}
          <Text style={styles.textBold}>배터리 정보</Text>를 관리해보세요
        </Text>
      </View>
      <View style={styles.right}>
        <Image
          style={styles.image}
          source={require("../assets/images/intro_battery.png")}
        />
      </View>
      <View style={styles.right}>
        <Text style={styles.text}>
          <Text style={styles.textBold}>정확한 배터리 정보</Text>를 {"\n"}
          <Text style={styles.textBold}>보험사</Text>에 보내줍니다 !
        </Text>
      </View>
      <View style={styles.left}>
        <Image
          style={styles.image}
          source={require("../assets/images/intro_car.png")}
        />
      </View>
      <View style={styles.buttonBox}>
        <Button
          mode="contained"
          style={styles.button}
          onPress={() => navigation.navigate("Register")}
          textColor={theme.white}
          labelStyle={{ fontSize: 18 }}
        >
          가입하기
        </Button>
        <Button onPress={() => navigation.navigate("Login")}>
          이미 회원이신가요?
        </Button>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    alignItems: "center",
    justifyContent: "center",
  },
  left: {
    marginRight: "auto",
    marginLeft: 30,
    paddingVertical: 15,
  },
  right: {
    marginLeft: "auto",
    marginRight: 30,
    paddingVertical: 15,
  },
  image: {
    width: 150,
    height: 150,
  },
  text: {
    fontSize: 25,
  },
  textBold: {
    fontWeight: "800",
  },
  buttonBox: {
    width: 200,
  },
  button: {
    marginVertical: 5,
  },
});
