import { StyleSheet, Text, View, Image } from "react-native";
import {
  Button,
  Dialog,
  Paragraph,
  Portal,
  Provider,
} from "react-native-paper";
import { theme } from "../../colors";
import MyPageModal from "../../component/MyPageModal";
import { useDispatch, useSelector } from "react-redux";
import { MaterialIcons } from "@expo/vector-icons";
import { logout } from "../../redux/auth";
import { useEffect, useState } from "react";
import axiosAPI from "../../api/axiosAPI";
import AsyncStorage from "@react-native-async-storage/async-storage";
import { ScrollView } from "react-native-gesture-handler";
import { FontAwesome } from "@expo/vector-icons";
import EcoCard from "../../component/EcoCard";
export default function MyPage({ navigation }) {
  const [cars, setCars] = useState([]);
  const [eco, setEco] = useState([]);
  const [user, setUser] = useState([]);
  // const user = useSelector((state) => state.auth.isLoggedIn);
  // const user = AsyncStorage.getItem("userInfo");
  // console.log(user);
  // console.log(user);
  const dispatch = useDispatch();
  const handleLogout = async () => {
    try {
      dispatch(logout());
      // console.log(user);
      // console.log("isLoggedIn after logout:", isLoggedIn);
      await AsyncStorage.removeItem("userInfo");
      await AsyncStorage.removeItem("userToken");
    } catch (error) {
      console.log(error);
    }
  };
  //모달 관련
  const [visible, setVisible] = useState(false);
  const showModal = () => setVisible(true);
  const hideModal = () => setVisible(false);
  const handleModal = () => {
    showModal();
  };

  //car 불러오기
  const getCars = async () => {
    try {
      await axiosAPI.get("/client/cars", {}).then((res) => {
        setCars(res.data);
      });
    } catch (error) {
      console.error(error);
    }
  };

  const getMyEco = async () => {
    //내 차 조회
    try {
      await axiosAPI.get("/client/bms/echo", {}).then((res) => {
        setEco(res.data);
        // console.log(res.data);
      });
      // console.log(items);
    } catch (error) {
      console.error(error);
    }
  };

  const getUserInfo = async () => {
    try {
      const userInfoString = await AsyncStorage.getItem("userInfo");
      const userInfo = JSON.parse(userInfoString);
      setUser(userInfo);
    } catch (error) {
      // AsyncStorage에서 데이터를 가져오는 중에 오류가 발생한 경우 처리 로직
      console.log("Error retrieving userInfo:", error);
    }
  };

  useEffect(() => {
    getUserInfo();
    getCars();
    getMyEco();
  }, []);

  //알림기능
  const handleNotification = () => {
    // console.log("click");
    navigation.navigate("MyNotification", { cars });
  };
  return (
    <Provider>
      <ScrollView>
        <View style={styles.container}>
          <View
            style={{
              flexDirection: "row",
              justifyContent: "space-between",
              alignItems: "center",
              marginHorizontal: 20,
            }}
          >
            <Text style={styles.hello}>
              <Text style={styles.helloBold}>{user.name}</Text>님 안녕하세요 !
            </Text>
            <View>
              <FontAwesome
                name="bell"
                size={24}
                color={theme.grey2}
                onPress={handleNotification}
              />
            </View>
            <Portal>
              {/* <Modal
              visible={visible}
              onDismiss={hideModal}
              contentContainerStyle={{
                backgroundColor: "white",
                padding: 20,
                height: 300,
                alignItems: "center",
                justifyContent: "center",
                alignSelf: "center",
                borderRadius: 10,
              }}
            >
              <Text>로그아웃 하시겠습니까?</Text>
            </Modal> */}
              <Dialog
                visible={visible}
                onDismiss={hideModal}
                style={{ backgroundColor: "#F4F5F6" }}
              >
                <Dialog.Content>
                  <Paragraph style={{ fontSize: 15 }}>
                    로그아웃 하시겠습니까?
                  </Paragraph>
                </Dialog.Content>
                <Dialog.Actions>
                  <Button onPress={hideModal} textColor="#7F7F7F">
                    취소
                  </Button>
                  <Button onPress={handleLogout} textColor="#167BFF">
                    로그아웃
                  </Button>
                </Dialog.Actions>
              </Dialog>
            </Portal>
          </View>
          <View style={styles.card}>
            <View>
              <Text style={styles.text}>나의 친환경 정보</Text>
              <Text style={{ color: theme.grey2, fontSize: 12 }}>
                {user.name}님의 전기차 운행으로 이정도의 효과를 내고 있어요 !
              </Text>
            </View>
            <View
              style={{ flexDirection: "row", justifyContent: "space-between" }}
            >
              <EcoCard
                title="연료 절감 비용"
                image="image1"
                data={eco.fuelSave / 10000}
                unit="만원"
              />
              <EcoCard
                title="탄소 절감 효과"
                image="image2"
                data={eco.carbonSave / 1000}
                unit="kg"
              />
              <EcoCard
                title="나무 심은 효과"
                image="image3"
                data={eco.treeSave}
                unit="그루"
              />
            </View>
          </View>
          <MyPageModal cars={cars} getCars={getCars} />
        </View>
        <Button
          onPress={handleModal}
          textColor={theme.grey2}
          style={{ padding: 20 }}
        >
          <Text>로그아웃</Text>
        </Button>
      </ScrollView>
    </Provider>
  );
}
const styles = StyleSheet.create({
  hello: {
    fontSize: 20,
    marginVertical: 20,
  },
  helloBold: {
    fontWeight: 800,
  },
  card: {
    backgroundColor: theme.white,
    borderRadius: 8,
    paddingVertical: 25,
    paddingHorizontal: 25,
    marginVertical: 10,
    marginHorizontal: 20,
    shadowColor: "#000",
    shadowOffset: {
      width: 0,
      height: 1,
    },
    shadowOpacity: 0.2,
    shadowRadius: 1.41,
    elevation: 2,
  },
  text: {
    fontSize: 15,
    fontWeight: 800,
  },
});
