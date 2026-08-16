add_subdirectory(CommonTools)

if (NOT MINGW)
  if (BUILD_FEXCONFIG)
    find_package(Qt6 COMPONENTS Qml Quick Widgets QUIET)
    if (NOT Qt6_FOUND)
      find_package(Qt5 COMPONENTS Qml Quick Widgets REQUIRED)
    endif()

    add_subdirectory(FEXConfig/)
  endif()

  if (BUILD_LAUNCHER OR BUILD_LAUNCHER_TUI)
    # Widgets only, deliberately: no Qml/Quick, so the launcher needs no QtQuick
    # scenegraph and therefore does not contend for the same GL/Vulkan stack the
    # guest titles are using. qt6-base is already a hard runtime dependency of
    # the package for FEXConfig, so this target adds no new ones.
    if (BUILD_LAUNCHER)
      find_package(Qt6 COMPONENTS Widgets QUIET)
      if (NOT Qt6_FOUND)
        find_package(Qt5 COMPONENTS Widgets REQUIRED)
      endif()
    endif()

    add_subdirectory(FastPPCx86Launcher/)
  endif()

  if (ENABLE_GDB_SYMBOLS)
    add_subdirectory(FEXGDBReader/)
  endif()

  if (NOT BUILD_STEAM_SUPPORT)
    add_subdirectory(FEXRootFSFetcher/)
  endif()

  add_subdirectory(FEXGetConfig/)
  add_subdirectory(FEXServer/)
  add_subdirectory(FEXBash/)
  add_subdirectory(FEXOfflineCompiler/)
  add_subdirectory(CodeSizeValidation/)
  add_subdirectory(LinuxEmulation/)

  add_subdirectory(FEXInterpreter/)
  add_subdirectory(Wow64Probe/)
  if (CMAKE_POSITION_INDEPENDENT_CODE)
    # C-ABI embedding library (Wine-facing). Needs a PIC-configured tree.
    add_subdirectory(FexBridge/)
  endif()
  add_subdirectory(pidof/)
  if (BUILD_TESTING)
    add_subdirectory(TestHarnessRunner/)
  endif()
endif()
