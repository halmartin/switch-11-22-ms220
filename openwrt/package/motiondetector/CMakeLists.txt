CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT(motiondetector)

ADD_EXECUTABLE(motiondetector motiondetector.cc)

SET(LIBAV_LDOPTS "-lavcodec -lavformat -lavdevice -lavutil")

IF(CROSS_COMPILE)
  TARGET_COMPILE_OPTIONS(motiondetector PRIVATE -DCROSS_COMPILE)
  TARGET_LINK_LIBRARIES(motiondetector LINK_PUBLIC ${LIBAV_LDOPTS})
  INSTALL(TARGETS motiondetector RUNTIME DESTINATION bin)
ELSE()
  SET(OPENCV_LDOPTS "-lswscale -lopencv_core -lopencv_highgui")
  FIND_PACKAGE(opencv REQUIRED)
  TARGET_LINK_LIBRARIES(motiondetector LINK_PUBLIC ${LIBAV_LDOPTS} ${OPENCV_LDOPTS})
  LINK_DIRECTORIES(/usr/local/lib)
ENDIF()


