# FastPPCx86 launcher: a GUI (Qt Widgets) and a TUI (ncurses) over one shared core.
#
# The core carries every bit of launch semantics and links neither toolkit, so
# `ppcx86-launch-tui` runs on a headless box with no Qt installed, the two
# frontends cannot drift from each other, and the launch path stays testable
# without a display.
#
# The installed commands are `ppcx86-launch` and `ppcx86-launch-tui`. The
# emulator binaries they invoke (FEX, FEXBash) and the FEX_* variables they
# export keep those names deliberately -- those are the emulator's interface and
# renaming them would break every existing config file and script.

add_library(FastPPCx86LauncherCore STATIC
  Registry.cpp Registry.h
  Session.cpp Session.h
  CLI.cpp CLI.h
  Json.cpp Json.h
  Runtimes.cpp Runtimes.h
  Discovery.cpp Discovery.h
  Topology.cpp Topology.h
  HostEnv.cpp HostEnv.h
  Recipes.cpp Recipes.h
  Hints.cpp Hints.h
  PrefixTools.cpp PrefixTools.h
  LaunchSpec.cpp LaunchSpec.h
  ProcessProbe.cpp ProcessProbe.h
  Runner.cpp Runner.h)

target_include_directories(FastPPCx86LauncherCore PUBLIC ${CMAKE_SOURCE_DIR}/Source/)
target_include_directories(FastPPCx86LauncherCore PRIVATE ${CMAKE_BINARY_DIR}/generated)
# CommonTools for PortabilityInfo.h (it exports its own directory).
target_link_libraries(FastPPCx86LauncherCore PUBLIC Common CommonTools)

set_target_properties(FastPPCx86LauncherCore PROPERTIES
  C_VISIBILITY_PRESET hidden
  CXX_VISIBILITY_PRESET hidden
  VISIBILITY_INLINES_HIDDEN TRUE)

# ---------------------------------------------------------------------------
# GUI: ppcx86-launch
# ---------------------------------------------------------------------------
if (BUILD_LAUNCHER)
set(CMAKE_AUTOMOC ON)

add_executable(ppcx86-launch
  Main.cpp
  MainWindow.cpp MainWindow.h
  PathsDialog.cpp PathsDialog.h
  TitleEditor.cpp TitleEditor.h
  ScanDialog.cpp ScanDialog.h)

if (Qt6_FOUND)
  target_link_libraries(ppcx86-launch PRIVATE FastPPCx86LauncherCore JemallocDummy Qt6::Widgets)
else()
  target_link_libraries(ppcx86-launch PRIVATE FastPPCx86LauncherCore JemallocDummy Qt5::Widgets)
endif()

LinkerGC(ppcx86-launch)

install(TARGETS ppcx86-launch RUNTIME
  DESTINATION bin
  COMPONENT Runtime)

install(FILES ppcx86-launch.desktop
  DESTINATION ${CMAKE_INSTALL_PREFIX}/share/applications/
  COMPONENT Runtime)

install(FILES icon.png
  DESTINATION ${CMAKE_INSTALL_PREFIX}/share/icons/hicolor/256x256/apps/
  RENAME ppcx86-launch.png
  COMPONENT Runtime)
endif()

# ---------------------------------------------------------------------------
# TUI: ppcx86-launch-tui
# ---------------------------------------------------------------------------
if (BUILD_LAUNCHER_TUI)
  # ncursesw rather than ncurses: title names carry non-ASCII regularly enough
  # (and the status column uses check marks), so the wide-character build is the
  # one that renders them correctly.
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(NCURSESW REQUIRED IMPORTED_TARGET ncursesw)

  add_executable(ppcx86-launch-tui
    TUI/Main.cpp
    TUI/UI.cpp TUI/UI.h
    TUI/App.cpp TUI/App.h)

  target_link_libraries(ppcx86-launch-tui PRIVATE FastPPCx86LauncherCore JemallocDummy PkgConfig::NCURSESW)

  LinkerGC(ppcx86-launch-tui)

  install(TARGETS ppcx86-launch-tui RUNTIME
    DESTINATION bin
    COMPONENT Runtime)
endif()
