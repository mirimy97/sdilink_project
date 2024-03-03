import axios from "axios";
import React, { useState } from "react";
import {
  KeyboardAvoidingView,
  StyleSheet,
  Text,
  TouchableOpacity,
  View,
} from "react-native";
import { Button, TextInput } from "react-native-paper";
import axiosAPI from "../../api/axiosAPI";
import { theme } from "../../colors";
export default function Register({ navigation }) {
  const [name, setName] = useState("");
  const [birth, setBirth] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [repassword, setRePassword] = useState("");
  const [nameError, setNameError] = useState("");
  const [birthError, setBirthError] = useState("");
  const [emailError, setEmailError] = useState("");
  const [passwordError, setPasswordError] = useState("");
  const [repasswordError, setRePasswordError] = useState("");

  const validate = () => {
    let name_pattern = /^[가-힣]{2,15}$/;
    let birth_pattern =
      /^(19[0-9][0-9]|20\d{2})-(0[0-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[0-1])$/;
    let email_pattern = /^[A-Za-z0-9_\.\-]+@[A-Za-z0-9\-]+\.[A-Za-z0-9\-]+/;
    let password_pattern =
      /^(?=.*[a-zA-z])(?=.*[0-9])(?=.*[$`~!@$!%*#^?&\\(\\)\-_=+]).{8,16}$/;
    if (name.length === 0) {
      setNameError("이름을 입력해주세요.");
    } else if (!name_pattern.test(name)) {
      setNameError(
        "특수문자,영어,숫자는 사용할수 없습니다. 한글만 입력하여주세요."
      );
    }
    if (birth.length === 0) {
      setBirthError("생년월일을 입력해주세요.");
    } else if (!birth_pattern.test(birth)) {
      setBirthError("YYYYMMDD 형식으로 입력해주세요.");
    }
    if (email.length === 0) {
      setEmailError("이메일을 입력해주세요.");
    } else if (!email_pattern.test(email)) {
      setEmailError("이메일 형식이 올바르지 않습니다.");
    }
    if (password.length === 0) {
      setPasswordError("비밀번호를 입력해주세요.");
    } else if (!password_pattern.test(password)) {
      setPasswordError(
        "영문, 숫자, 특수문자를 조합해서 입력해주세요. (8-16자)"
      );
    }
    if (repassword.length === 0) {
      setRePasswordError("비밀번호를 재입력해주세요.");
    } else if (password !== repassword) {
      setRePasswordError("비밀번호가 일치하지 않습니다.");
    } else {
      setNameError("");
      setBirthError("");
      setEmailError("");
      setPasswordError("");
      setRePasswordError("");
      // console.log("확인");
      handleRegist();
    }
  };

  const handleRegist = async () => {
    await axiosAPI
      .post(
        "/client/regist",
        {
          userId: email,
          userPwd: password,
          name: name,
          birth: birth,
        },
        {
          headers: {
            "Content-Type": "application/json",
          },
        }
      )
      .then((response) => {
        // console.log(response);
        navigation.navigate("Welcome");
      });
  };
  return (
    <KeyboardAvoidingView
      behavior={Platform.select({ ios: "padding", android: undefined })}
      style={styles.container}
    >
      <View>
        <View style={styles.inputBox}>
          <Text style={styles.text}>이름</Text>
          <TextInput
            style={styles.input}
            // dense
            value={name}
            placeholder="이름을 입력해주세요."
            onChangeText={(text) => setName(text)}
          />
          <Text style={styles.error}>{nameError}</Text>
        </View>
        <View style={styles.inputBox}>
          <Text style={styles.text}>생년월일</Text>
          <TextInput
            style={styles.input}
            keyboardType="number-pad"
            // dense
            value={birth}
            placeholder="예) YYMMDD"
            onChangeText={(text) => setBirth(text)}
          />
          <Text style={styles.error}>{birthError}</Text>
        </View>
        <View style={styles.inputBox}>
          <Text style={styles.text}>이메일 아이디</Text>
          <TextInput
            style={styles.input}
            keyboardType="email-address"
            value={email}
            placeholder="예) sdilink@sdilink.co.kr"
            onChangeText={(text) => setEmail(text)}
            autoCapitalize="none"
          />
          <Text style={styles.error}>{emailError}</Text>
        </View>
        <View style={styles.inputBox}>
          <Text style={styles.text}>패스워드</Text>
          <TextInput
            style={styles.input}
            value={password}
            placeholder="영문, 숫자, 특수문자를 조합 8-16자"
            onChangeText={(text) => setPassword(text)}
            secureTextEntry={true}
            autoCapitalize="none"
          />
          <Text style={styles.error}>{passwordError}</Text>
        </View>
        <View style={styles.inputBox}>
          <Text style={styles.text}>패스워드 재입력</Text>
          <TextInput
            style={styles.input}
            value={repassword}
            placeholder="패스워드를 재입력해주세요."
            onChangeText={(text) => setRePassword(text)}
            secureTextEntry={true}
            autoCapitalize="none"
          />
          <Text style={styles.error}>{repasswordError}</Text>
        </View>
        <Button style={styles.button} onPress={validate}>
          회원가입
        </Button>
      </View>
    </KeyboardAvoidingView>
  );
}
const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: "center",
    alignItems: "center",
  },
  inputBox: {
    width: 300,
    marginBottom: 12,
  },
  text: {
    fontWeight: 800,
    fontSize: 12,
  },
  input: {
    borderRadius: 10,
    borderColor: "lightgray",
    backgroundColor: "white",
    marginTop: 10,
    fontSize: 12,
    height: 45,
  },
  error: {
    color: "red",
  },
  button: {
    marginLeft: "auto",
  },
});
