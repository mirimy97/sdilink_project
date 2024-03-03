import { useRoute } from "@react-navigation/native";
import { useEffect, useState } from "react";
import { StyleSheet, Text, View } from "react-native";
import axiosAPI from "../../api/axiosAPI";
import { theme } from "../../colors";
import HalfPieChart from "../../component/HalfPieChart";

export default function CellPage({ route }) {
  const { md } = route.params;

  const [cells, setCells] = useState([]);
  useEffect(() => {
    const getCell = async () => {
      try {
        await axiosAPI.get(`/client/bms/modules/${md.id}`, {}).then((res) => {
          console.log(res.data);
          setCells(res.data);
        });
        // console.log(items);
      } catch (error) {
        console.error(error);
      }
    };

    getCell();
  }, []);

  const Hexagon = ({ cell }) => {
    if (cell.isNormal == -1) {
      return (
        <View style={styles.hexagon}>
          <View
            style={{ ...styles.hexagonInner, backgroundColor: theme.error }}
          >
            <View
              style={{
                flex: 1,
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <Text style={{ textAlign: "center", fontSize: 9 }}>
                {cell.cellCode}
              </Text>
              <Text style={{ textAlign: "center", fontSize: 14 }}>
                {Math.round(cell.voltageC)}V
              </Text>
            </View>
          </View>
          <View
            style={{ ...styles.hexagonBefore, borderBottomColor: theme.error }}
          />
          <View
            style={{ ...styles.hexagonAfter, borderTopColor: theme.error }}
          />
        </View>
      );
    } else {
      return (
        <View style={styles.hexagon}>
          <View style={styles.hexagonInner}>
            <View
              style={{
                flex: 1,
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <Text style={{ textAlign: "center", fontSize: 9 }}>
                {cell.cellCode}
              </Text>
              <Text style={{ textAlign: "center", fontSize: 14 }}>
                {Math.round(cell.voltageC)}V
              </Text>
            </View>
          </View>
          <View style={styles.hexagonBefore} />
          <View style={styles.hexagonAfter} />
        </View>
      );
    }
  };

  return (
    <View style={styles.container}>
      <View style={styles.view}>
        <View style={styles.box}>
          <Text style={styles.text}>배터리 상세</Text>
          <View style={styles.card}>
            {md.outlier ? (
              <View>
                <Text>문제 있는 셀이 발견되었습니다.</Text>
                <Text>가까운 정비소를 방문해주세요.</Text>
              </View>
            ) : (
              <View>
                <Text>모든 셀들에 문제가 없습니다.</Text>
                <Text>문제시 해당 셀의 색이 변경됩니다.</Text>
              </View>
            )}

            <View style={{ ...styles.flex, left: -7, top: 50 }}>
              {cells.slice(0, 4).map((cell, index) => (
                <Hexagon key={index} cell={cell} />
              ))}
            </View>
            <View style={{ ...styles.flex, left: 25, top: 25 }}>
              {cells.slice(4, 8).map((cell, index) => (
                <Hexagon key={index} cell={cell} />
              ))}
            </View>
            <View style={{ ...styles.flex, left: -7 }}>
              {cells.slice(8, 12).map((cell, index) => (
                <Hexagon key={index} cell={cell} />
              ))}
            </View>
          </View>
        </View>
      </View>

      <View style={{ ...styles.view, marginTop: 70 }}>
        <Text style={{ ...styles.text, marginHorizontal: 10 }}>
          배터리 모듈 정보
        </Text>
        <View style={{ flexDirection: "row" }}>
          <View style={styles.box}>
            <View
              style={{
                ...styles.card,
                height: 130,
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <Text style={styles.cardText}>전압</Text>
              <Text style={{ fontSize: 9, marginVertical: 5 }}>
                정상 범위 : 75.6V ~ 100.8V
              </Text>
              <Text
                style={{
                  marginVertical: 10,
                  fontSize: 22,
                  fontWeight: 700,
                  color: theme.blue,
                }}
              >
                {Math.round(md.voltage)}V
              </Text>
            </View>
          </View>
          <View style={styles.box}>
            <View
              style={{
                ...styles.card,
                height: 130,
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <Text style={styles.cardText}>전류</Text>
              <Text style={{ fontSize: 9, marginVertical: 5 }}>
                정상 범위 : +15 ℃ ~ +45 ℃
              </Text>
              <Text
                style={{
                  marginVertical: 10,
                  fontSize: 22,
                  fontWeight: 700,
                  color: theme.blue,
                }}
              >
                {Math.round(md.temp)}℃
              </Text>
            </View>
          </View>
        </View>
      </View>
    </View>
  );
}
const styles = StyleSheet.create({
  container: {
    flex: 1,
  },
  view: {
    flex: 1,
    marginHorizontal: 10,
    marginVertical: 20,
  },
  text: {
    fontWeight: 800,
    fontSize: 15,
    marginBottom: 5,
  },
  box: {
    flex: 1,
    marginHorizontal: 10,
  },
  flex: {
    flex: 1,
    flexDirection: "row",
    justifyContent: "space-evenly",
  },
  card: {
    backgroundColor: theme.white,
    borderRadius: 8,
    height: 300,
    paddingVertical: 10,
    paddingHorizontal: 25,
    shadowColor: theme.grey2,
    shadowOffset: {
      width: 0,
      height: 1,
    },
    shadowOpacity: 0.2,
    shadowRadius: 1.41,
    elevation: 2,
  },
  cardText: {
    fontSize: 15,
    fontWeight: 800,
  },

  //육각형
  hexagon: {
    width: 60,
    height: 30,
    marginBottom: -10, // 아래로 이동
    marginLeft: -5, // 왼쪽으로 이동
  },
  hexagonInner: {
    width: 60,
    height: 30,
    backgroundColor: theme.blue0,
  },
  hexagonAfter: {
    position: "absolute",
    bottom: -19,
    left: 0,
    width: 0,
    height: 0,
    borderStyle: "solid",
    borderLeftWidth: 30,
    borderLeftColor: "transparent",
    borderRightWidth: 30,
    borderRightColor: "transparent",
    borderTopWidth: 20,
    borderTopColor: theme.blue0,
  },
  hexagonBefore: {
    position: "absolute",
    top: -20,
    left: 0,
    width: 0,
    height: 0,
    borderStyle: "solid",
    borderLeftWidth: 30,
    borderLeftColor: "transparent",
    borderRightWidth: 30,
    borderRightColor: "transparent",
    borderBottomWidth: 20,
    borderBottomColor: theme.blue0,
  },
});
