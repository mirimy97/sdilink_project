import React, { useEffect, useRef, useState } from "react";
import { Dimensions, Image, StyleSheet, Text, View } from "react-native";
import * as Location from "expo-location";
import MapView, { Callout, Marker } from "react-native-maps";
import { debounce } from "lodash";
import {
  ActivityIndicator,
  Button,
  Checkbox,
  Modal,
  Portal,
  Provider,
} from "react-native-paper";
import { Ionicons } from "@expo/vector-icons";
import { theme } from "../../colors.js";
import ChargingBox from "../../component/ChargingBox.js";
import MarkerInfoBox from "../../component/MarkerInfoBox.js";
import SlidingUpPanel from "rn-sliding-up-panel";
import markerIcon from "../../assets/images/gas-station.png";
export default function Charging() {
  const mapRef = useRef(null);
  const [location, setLocation] = useState();
  const [regioncode, setRegioncode] = useState();
  const [ok, setOk] = useState(true);
  const [markers, setMarkers] = useState([]); //마커 배열
  const [markerStatus, setMarkerStatus] = useState([
    "DC차데모",
    "AC완속",
    "AC3상",
    "DC콤보",
  ]);

  //마커별 충전기 상태 저장
  const [isPanelVisible, setIsPanelVisible] = useState();

  //옵션 창 오픈
  const [visible, setVisible] = useState(false);
  //마커 정보
  const [markerInfo, setMarkerInfo] = useState([]);
  const showModal = (buttonId, marker) => {
    if (buttonId == "option") {
      //옵션 클릭했을때
      setVisible(true);
    } else if (buttonId == "marker") {
      //마커 클릭했을때
      console.log("clck");
      this._panel.show();
      setMarkerInfo(marker);
      setIsPanelVisible(true);
    }
  };
  // const hideModal = () => setVisible(false);

  //zCode Object
  const zCode = {
    서울특별시: "11",
    부산광역시: "26",
    대구광역시: "27",
    인천광역시: "28",
    광주광역시: "29",
    대전광역시: "30",
    울산광역시: "31",
    세종특별자치시: "36",
    경기도: "41",
    강원도: "42",
  };

  //지도 켜자마자 현재 위치 받아오기
  const ask = async () => {
    const { granted } = await Location.requestForegroundPermissionsAsync();
    if (!granted) {
      setOk(false);
    }
    const { coords } = await Location.getCurrentPositionAsync({});
    setLocation(coords);

    const geocodeResult = await Location.reverseGeocodeAsync({
      latitude: coords.latitude,
      longitude: coords.longitude,
    });
    setRegioncode(geocodeResult[0].region);
  };

  //현재위치 클릭했을때
  const currentLocation = () => {
    mapRef.current.animateToRegion({
      latitude: location.latitude,
      longitude: location.longitude,
      latitudeDelta: 0.05,
      longitudeDelta: 0.05,
    });

    handleRegionChangeComplete();
  };

  //위치 이동시마다 API 불러오기
  const handleRegionChangeComplete = debounce(async (region) => {
    //충전소 정보 불러오기
    const response = await fetch(
      `http://apis.data.go.kr/B552584/EvCharger/getChargerInfo?serviceKey=${`%2BKTJ%2F06CtJnKsOXMUdQYslb89yCAQaMsHgNDc%2FnskEU91SLUyWYyMmaEIfz9l3%2BVlWGI%2FbEMsX3z6Bw5uEEsPA%3D%3D`}&numOfRows=9999&zcode=${
        zCode[regioncode]
      }&pageNo=1&dataType=JSON`
    );

    const json = await response.json();
    // console.log("json.item", json.items);

    const filteredMarkers = json.items.item.filter(
      (marker) =>
        marker.lat >= region.latitude - region.latitudeDelta &&
        marker.lat <= region.latitude + region.latitudeDelta &&
        marker.lng >= region.longitude - region.longitudeDelta &&
        marker.lng <= region.longitude + region.longitudeDelta
    );
    // console.log("filter", filteredMarkers);
    setMarkers(filteredMarkers);
  }, 1000);

  const searchOption = (chargeType, parkType) => {
    setVisible(false);
    // console.log(chargeType);
    // console.log(parkType);
  };

  useEffect(() => {
    ask(); //요청
  }, []);

  if (location) {
    const { latitude, longitude } = location;
    return (
      <Provider>
        <View style={styles.container}>
          <MapView
            style={styles.map}
            showsUserLocation={true}
            initialRegion={{
              latitude: latitude,
              longitude: longitude,
              latitudeDelta: 0.05,
              longitudeDelta: 0.05,
            }}
            minZoomLevel={13}
            onRegionChangeComplete={handleRegionChangeComplete}
            ref={mapRef}
          >
            {markers &&
              markers.map((marker, index) => (
                <Marker
                  key={index}
                  coordinate={{
                    latitude: parseFloat(marker.lat),
                    longitude: parseFloat(marker.lng),
                  }}
                  onPress={() => showModal("marker", marker)}
                  style={{ width: 10, height: 10 }}
                  icon={markerIcon}
                  // onPress={() => handleMarkerPress(marker)}
                >
                  <Callout>
                    <Text
                      style={{
                        fontWeight: 800,
                        fontSize: 10,
                        width: 80,
                        alignItems: "center",
                        textAlign: "center",
                      }}
                    >
                      {marker.statNm}
                    </Text>
                  </Callout>
                </Marker>
              ))}
          </MapView>
          <Portal>
            <Modal visible={visible} onDismiss={() => setVisible(false)}>
              <ChargingBox searchOption={searchOption} />
            </Modal>
          </Portal>
          <SlidingUpPanel
            visible={isPanelVisible}
            ref={(c) => (this._panel = c)}
            draggableRange={{ top: 150, bottom: 0 }}
            height={150}
            onDragStart={this._hidePanel}
            backdropOpacity={0}
          >
            <MarkerInfoBox markerInfo={markerInfo} />
          </SlidingUpPanel>
          {/* <View style={styles.iconBox}>
            <Ionicons
              name="locate"
              size={24}
              color="black"
              style={styles.icon}
              onPress={currentLocation}
            />
            <Ionicons
              name="options"
              size={24}
              color="black"
              style={{ ...styles.icon, marginRight: 10 }}
              onPress={() => showModal("option", "")}
            />
          </View> */}
        </View>
      </Provider>
    );
  } else {
    return (
      <ActivityIndicator
        color="white"
        style={{ flex: 1, justifyContent: "center" }}
        size="large"
      />
    );
  }
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
  },
  map: {
    width: "100%",
    height: "100%",
  },
  iconBox: {
    position: "absolute",
    bottom: 0,
    right: 0,
    flexDirection: "row",
  },
  icon: {
    backgroundColor: theme.white,
    padding: 3,
    color: theme.grey2,
    marginHorizontal: 5,
    marginVertical: 10,
  },
  markerBox: {
    position: "absolute",
    bottom: 0,
    width: "100%",
    height: 200,
  },
});
