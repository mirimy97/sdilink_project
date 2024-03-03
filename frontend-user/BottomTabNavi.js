import { createBottomTabNavigator } from "@react-navigation/bottom-tabs";
import { createStackNavigator } from "@react-navigation/stack";
import React from "react";
import BatteryMon from "./pages/PageComponent/BatteryMon";
import MyPage from "./pages/PageComponent/MyPage";
import BatteryPre from "./pages/PageComponent/BatteryPre";
import Charging from "./pages/PageComponent/Charging";
import CellPage from "./pages/PageComponent/CellPage";
import { DefaultTheme, Provider as PaperProvider } from "react-native-paper";
import MyNotification from "./pages/PageComponent/MyNotification";
import { FontAwesome5 } from "@expo/vector-icons";
import { FontAwesome } from "@expo/vector-icons";
import { Entypo } from "@expo/vector-icons";

const BottomTab = createBottomTabNavigator();
const Stack = createStackNavigator();

function BatteryMonStackScreen() {
  return (
    <Stack.Navigator>
      <Stack.Screen
        name="BatteryMon"
        options={{ headerShown: false }}
        component={BatteryMon}
      />
      <Stack.Screen
        name="CellPage"
        options={{ headerShown: false }}
        component={CellPage}
      />
    </Stack.Navigator>
  );
}
function MyPageStackScreen() {
  return (
    <Stack.Navigator>
      <Stack.Screen
        name="MyPage"
        options={{ headerShown: false }}
        component={MyPage}
      />
      <Stack.Screen
        name="MyNotification"
        options={{ headerShown: false }}
        component={MyNotification}
      />
    </Stack.Navigator>
  );
}
export default function BottomTabNavi() {
  const theme = {
    ...DefaultTheme,
    colors: {
      ...DefaultTheme.colors,
      primary: "#167BFF",
      accent: "#1428A0",
      primaryContainer: "#D9EAFF",
      secondaryContainer: "#D9EAFF",
      surface: "#D9EAFF",
      background: "#F4F5F6",
      text: "#FFFFFF",
    },
  };
  return (
    <PaperProvider theme={theme}>
      <BottomTab.Navigator initialRouteName="배터리 모니터링">
        <BottomTab.Screen
          name="배터리 모니터링"
          component={BatteryMonStackScreen}
          options={{
            tabBarIcon: ({ color, size }) => (
              <FontAwesome5 name="car-battery" color={color} size={size} />
            ),
          }}
        />
        <BottomTab.Screen
          name="배터리 예측"
          component={BatteryPre}
          options={{
            tabBarIcon: ({ color, size }) => (
              <Entypo name="area-graph" color={color} size={size + 1} />
            ),
          }}
        />
        <BottomTab.Screen
          name="충전소 정보"
          component={Charging}
          options={{
            tabBarIcon: ({ color, size }) => (
              <FontAwesome5 name="charging-station" color={color} size={size} />
            ),
          }}
        />
        <BottomTab.Screen
          name="마이 페이지"
          component={MyPageStackScreen}
          options={{
            tabBarIcon: ({ color, size }) => (
              <FontAwesome name="user" color={color} size={size} />
            ),
          }}
        />
      </BottomTab.Navigator>
    </PaperProvider>
  );
}
