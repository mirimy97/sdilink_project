import { StyleSheet, View, Text } from "react-native";
import { theme } from "../colors";
import { AntDesign } from "@expo/vector-icons";
import { Button, Modal, Portal, TextInput } from "react-native-paper";
import { useEffect, useState } from "react";
import { Dropdown } from "react-native-paper";
import { SelectList } from "react-native-dropdown-select-list";
import axiosAPI from "../api/axiosAPI";
import { Toast } from "react-native-toast-message/lib/src/Toast";
import { FontAwesome } from "@expo/vector-icons";
export default function MyPageModal({ cars, getCars }) {
  //모달 관련
  const [visible, setVisible] = useState(false);
  const showModal = () => setVisible(true);
  const hideModal = () => setVisible(false);

  //모달 안 드롭다운 관련

  const [carNum, setCarNum] = useState("");

  //select box 관련

  const [selected, setSelected] = useState("");

  const [option, setOption] = useState([]);
  useEffect(() => {
    const getOption = async () => {
      try {
        await axiosAPI.get("/client/carinfos", {}).then((res) => {
          const resdata = res.data;
          const options = resdata.map((op) => {
            const id = `${op.id}`;
            const car = `${op.maker} ${op.modelName}`;
            return {
              key: id,
              value: car,
            };
          });
          setOption(options);
        });
      } catch (error) {
        console.error(error);
      }
    };

    getOption();
  }, []);

  const handleCarRegist = async () => {
    try {
      console.log(selected);
      console.log(carNum);
      await axiosAPI
        .post("/client/cars", { carInfoId: selected, carNumber: carNum }, {})
        .then((res) => {
          if (res.data.carId) {
            Toast.show({
              type: "success",
              text1: "등록이 완료되었습니다.",
            });
            hideModal();
            getCars();
          } else {
            Toast.show({
              type: "error",
              text1: "정보가 없습니다.",
            });
          }
        });
    } catch (error) {
      console.error(error);
    }
  };

  const handleDelete = async (id) => {
    try {
      // console.log(id);
      await axiosAPI.delete(`/client/cars/${id}`, {}).then((res) => {
        if (res.data.car_id) {
          Toast.show({
            type: "success",
            text1: "삭제가 완료 되었습니다.",
          });

          getCars();
        } else {
          Toast.show({
            type: "error",
            text1: "정보가 없습니다.",
          });
        }
      });
    } catch (error) {
      console.error(error);
    }
  };
  return (
    <View style={styles.card}>
      <View style={styles.car}>
        <Text style={styles.text}>나의 차량 정보</Text>
        <AntDesign
          onPress={showModal}
          name="plussquareo"
          size={20}
          color="black"
        />
        <Portal>
          <Modal
            visible={visible}
            onDismiss={hideModal}
            contentContainerStyle={{
              backgroundColor: "white",
              padding: 20,
              alignItems: "center",
              justifyContent: "center",
              alignSelf: "center",
              borderRadius: 10,
            }}
          >
            <View style={styles.inputBox}>
              <Text style={{ ...styles.text, marginBottom: 7 }}>
                차 종 선택
              </Text>
              <SelectList
                setSelected={(id) => {
                  setSelected(id);
                  // console.log(id);
                }}
                data={option}
                save="id"
                placeholder="차종을 선택해주세요."
              />
            </View>
            <View style={styles.inputBox}>
              <Text style={styles.text}>차량 번호</Text>
              <TextInput
                style={styles.input}
                value={carNum}
                placeholder="차 번호를 입력해주세요."
                onChangeText={(text) => setCarNum(text)}
                autoCapitalize="none"
                activeUnderlineColor={theme.blue}
                autoCorrect={false}
              />
            </View>
            <Button
              mode="contained"
              onPress={handleCarRegist}
              style={styles.button}
            >
              등록
            </Button>
          </Modal>
        </Portal>
      </View>
      {/* <Text>차량 정보를 등록해주세요 !</Text> */}
      {cars.length !== 0 ? (
        cars.map((car, index) => (
          <View
            key={index}
            style={{
              borderBottomWidth: 1,
              borderBottomColor: theme.grey,
              paddingBottom: 10,
            }}
          >
            <View style={styles.carBox}>
              <View>
                <Text
                  style={{ fontSize: 14, fontWeight: 700, color: theme.blue }}
                >
                  {car.maker} {car.modelName}
                </Text>
                <Text>차 번호 {car.carNumber}</Text>
              </View>
              <View>
                <Text style={{ fontWeight: 500 }}>배터리팩 코드</Text>
                <Text style={{ marginLeft: "auto", fontWeight: 500 }}>
                  {car.packCode}
                </Text>
              </View>
            </View>
            <View style={{ flexDirection: "row", alignItems: "center" }}>
              <Text style={styles.date}>
                {car.createdAt.replace("T", " ").slice(0, -7)}
              </Text>
              <FontAwesome
                name="trash-o"
                size={20}
                style={{ marginLeft: 6, color: theme.error }}
                onPress={() => handleDelete(car.id)}
              />
            </View>
          </View>
        ))
      ) : (
        <View>
          <Text style={{ marginVertical: 15, fontSize: 12 }}>
            차량 정보를 등록해주세요.
          </Text>
        </View>
      )}
    </View>
  );
}
const styles = StyleSheet.create({
  card: {
    backgroundColor: theme.white,
    borderRadius: 8,
    paddingVertical: 25,
    paddingHorizontal: 25,
    marginVertical: 10,
    marginHorizontal: 20,
    shadowColor: theme.grey2,
    shadowOffset: {
      width: 0,
      height: 1,
    },
    shadowOpacity: 0.2,
    shadowRadius: 1.41,
    elevation: 2,
  },
  car: {
    flexDirection: "row",
    justifyContent: "space-between",
  },
  carBox: {
    flexDirection: "row",
    justifyContent: "space-between",
    marginVertical: 13,
    alignItems: "center",
  },
  date: {
    marginLeft: "auto",
    fontSize: 12,
    color: theme.grey2,
  },

  inputBox: {
    width: 300,
    marginVertical: 15,
  },
  text: {
    fontWeight: 800,
    fontSize: 15,
  },
  input: {
    borderRadius: 10,
    borderColor: "lightgray",
    backgroundColor: "white",
    marginTop: 10,
    fontSize: 12,
    height: 45,
  },
  button: {
    backgroundColor: theme.blue,
    marginLeft: "auto",
  },
});
