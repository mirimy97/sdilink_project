import { useState, useEffect, useRef } from "react";
import BottomTabNavi from "./BottomTabNavi";
import { NavigationContainer, useNavigation } from "@react-navigation/native";
import Login from "./pages/User/Login";
import Register from "./pages/User/Register";
import Intro from "./pages/Intro";
import { createStackNavigator } from "@react-navigation/stack";
import { Provider as PaperProvider } from "react-native-paper";
import { Provider as ReduxProvider, useDispatch } from "react-redux";
import { useSelector } from "react-redux";
import Welcome from "./pages/User/Welcome";
import { Toast } from "react-native-toast-message/lib/src/Toast";
import store from "./redux/store";
import * as Device from "expo-device";
import * as Notifications from "expo-notifications";
import { Text, View, Button, Platform } from "react-native";
import AsyncStorage from "@react-native-async-storage/async-storage";
import { login } from "./redux/auth";
import axiosAPI from "./api/axiosAPI";

const Stack = createStackNavigator();

Notifications.setNotificationHandler({
  handleNotification: async () => ({
    shouldShowAlert: true,
    shouldPlaySound: true,
    shouldSetBadge: false,
  }),
});

export default function App() {
  const [expoPushToken, setExpoPushToken] = useState("");
  const [notification, setNotification] = useState(false);
  const notificationListener = useRef();
  const responseListener = useRef();

  const theme = {
    roundness: 2,
    colors: {
      primary: "#167BFF",
      accent: "#1428A0",
      background: "#F4F5F6",
      text: "#FFFFFF",
    },
  };

  useEffect(() => {
    registerForPushNotificationsAsync().then((token) =>
      setExpoPushToken(token)
    );

    notificationListener.current =
      Notifications.addNotificationReceivedListener((notification) => {
        setNotification(notification);
      });

    responseListener.current =
      Notifications.addNotificationResponseReceivedListener((response) => {
        console.log(response);
      });

    return () => {
      Notifications.removeNotificationSubscription(
        notificationListener.current
      );
      Notifications.removeNotificationSubscription(responseListener.current);
    };
  }, []);

  return (
    <ReduxProvider store={store}>
      <PaperProvider theme={theme}>
        <NavigationContainer>
          <MainNavigator expoPushToken={expoPushToken} />
        </NavigationContainer>
        <Toast />
      </PaperProvider>
    </ReduxProvider>
  );
}

function MainNavigator({ expoPushToken }) {
  const dispatch = useDispatch();
  const isLoggedIn = useSelector((state) => state.auth.isLoggedIn);
  // // const isLoggedIn = true;
  // const navigation = useNavigation();
  // const responseListener = useRef();

  useEffect(() => {
    checkAutoLogin();
  }, []);

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

  //자동 로그인을 위해서
  const checkAutoLogin = async () => {
    try {
      const userInfoString = await AsyncStorage.getItem("userInfo");
      const userToken = await AsyncStorage.getItem("userToken");
      if (userInfoString.length > 2 && userToken.length > 0) {
        const userInfo = JSON.parse(userInfoString);
        // console.log("if", userInfo);
        // console.log("if", userToken);
        dispatch(login(userInfo));
        // accessToken 설정
        expoToken(expoPushToken);
        Toast.show({
          type: "success",
          text1: "자동 로그인 완료",
        });
      }
    } catch (error) {
      console.log(error);
    }
  };

  return isLoggedIn ? (
    <BottomTabNavi />
  ) : (
    <Stack.Navigator>
      <Stack.Screen
        name="Intro"
        component={Intro}
        options={{ headerShown: false }}
      />
      <Stack.Screen
        name="Login"
        component={Login}
        options={{ headerShown: false }}
        initialParams={{ expoPushToken: expoPushToken }}
      />
      <Stack.Screen
        name="Register"
        component={Register}
        options={{ headerShown: false }}
      />
      <Stack.Screen
        name="Welcome"
        component={Welcome}
        options={{ headerShown: false }}
      />
      <Stack.Screen
        name="Home"
        component={BottomTabNavi}
        options={{ headerShown: false }}
      />
    </Stack.Navigator>
  );
}

async function registerForPushNotificationsAsync() {
  let token;

  if (Platform.OS === "android") {
    await Notifications.setNotificationChannelAsync("default", {
      name: "default",
      importance: Notifications.AndroidImportance.MAX,
      vibrationPattern: [0, 250, 250, 250],
      lightColor: "#FF231F7C",
    });
  }

  if (Device.isDevice) {
    const { status: existingStatus } =
      await Notifications.getPermissionsAsync();
    let finalStatus = existingStatus;
    if (existingStatus !== "granted") {
      const { status } = await Notifications.requestPermissionsAsync();
      finalStatus = status;
    }
    if (finalStatus !== "granted") {
      alert("Failed to get push token for push notification!");
      return;
    }
    token = (
      await Notifications.getExpoPushTokenAsync({
        projectId: "3395f4e0-111c-49f2-afa6-f3d562ef1519",
      })
    ).data;
    console.log(token);
  } else {
    alert("Must use physical device for Push Notifications");
  }

  return token;
}
