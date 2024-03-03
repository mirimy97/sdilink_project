import React, { useState } from "react";
import { StyleSheet, Text, TouchableOpacity, View } from "react-native";
import { Button, TextInput } from "react-native-paper";
import { theme } from "../../colors";
import AsyncStorage from "@react-native-async-storage/async-storage";
import { Toast } from "react-native-toast-message/lib/src/Toast";
import { useDispatch, useSelector } from "react-redux";
import { login } from "../../redux/auth";
import axiosAPI from "../../api/axiosAPI";

export default function Login({ navigation, route }) {
  const { expoPushToken } = route.params;

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [emailError, setEmailError] = useState("");
  const [passwordError, setPasswordError] = useState("");

  const dispatch = useDispatch();

  const validate = () => {
    let email_pattern = /^[A-Za-z0-9_\.\-]+@[A-Za-z0-9\-]+\.[A-Za-z0-9\-]+/;

    if (email.length === 0) {
      setEmailError("이메일을 입력해주세요.");
    } else if (!email_pattern.test(email)) {
      setEmailError("이메일 형식이 올바르지 않습니다.");
    }
    if (password.length === 0) {
      setPasswordError("비밀번호를 입력해주세요.");
    } else {
      setEmailError("");
      setPasswordError("");
      // console.log("확인");
      handleLogin();
    }
  };

  // 로그인 성공 후 토큰 저장
  const storeToken = async (token) => {
    try {
      await AsyncStorage.setItem("userToken", token);
    } catch (error) {
      console.error(error);
    }
  };

  // 로그인 성공 후 유저 정보 저장
  const storeUserInfo = async (userInfo) => {
    try {
      const user = JSON.stringify(userInfo);
      await AsyncStorage.setItem("userInfo", user);
    } catch (error) {
      console.error(error);
    }
  };
  const handleLogin = async () => {
    await axiosAPI
      .post("/client/login", {
        id: email,
        password: password,
      })
      .then((res) => {
        console.log(res.data);
        if (res.status == 200) {
          // console.log(res.data);
          const user = {
            userid: res.data.id,
            birth: res.data.birth,
            name: res.data.name,
          };
          dispatch(login(user));
          const accessToken = res.headers.get("authorization");
          storeToken(accessToken); //토큰 저장
          storeUserInfo(user); //유저 정보 저장
          expoToken(expoPushToken); //토큰 넘겨주기
          Toast.show({
            type: "success",
            text1: "로그인 완료",
          });
          setTimeout(() => {
            navigation.navigate("Home");
          }, 1000);
        }
      })
      .catch((error) => {
        Toast.show({
          type: "error",
          text1: "로그인 정보가 없습니다.",
        });
        console.error(error);
      });
  };

  const expoToken = async (expoPushToken) => {
    console.log("expo", expoPushToken);
    try {
      await axiosAPI.post(
        "/client/expo-token",
        {
          expoToken: expoPushToken,
        },
        {}
      );
    } catch (error) {
      console.log(error);
    }
  };
  return (
    <View style={styles.container}>
      <View style={styles.inputBox}>
        <Text style={styles.text}>이메일 아이디</Text>
        <TextInput
          style={styles.input}
          value={email}
          placeholder="이메일 아이디를 입력해주세요."
          onChangeText={(text) => setEmail(text)}
          autoCapitalize="none"
        />
        <Text style={styles.error}>{emailError}</Text>
      </View>
      <View style={styles.inputBox}>
        <Text style={styles.text}>비밀번호</Text>
        <TextInput
          style={styles.input}
          value={password}
          placeholder="패스워드를 입력해주세요."
          onChangeText={(text) => setPassword(text)}
          secureTextEntry={true}
          autoCapitalize="none"
        />
        <Text style={styles.error}>{passwordError}</Text>
      </View>
      {/* <TouchableOpacity style={styles.button} onPress={this.handleLogin}>
        <Text style={styles.buttonText}>Login</Text>
      </TouchableOpacity> */}
      <Button
        mode="contained"
        style={styles.button}
        textColor={theme.white}
        onPress={validate}
      >
        로그인
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
  inputBox: {
    width: 300,
    marginVertical: 10,
  },
  text: {
    fontWeight: 800,
    fontSize: 12,
  },
  input: {
    borderRadius: 15,
    borderColor: "lightgray",
    backgroundColor: "white",
    marginTop: 10,
    fontSize: 12,
    height: 45,
  },
  button: {
    width: 300,
    marginVertical: 12,
  },
  error: {
    color: "red",
  },
});
