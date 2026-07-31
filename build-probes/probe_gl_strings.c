// Minimal GL/GLX string probe.
//
// Prints glGetString results (VENDOR/RENDERER/VERSION/SHADING_LANGUAGE_VERSION),
// a sample of glGetStringi(GL_EXTENSIONS,0), and the three glX*String returns.
// Also prints identity: repeats glGetString(GL_VENDOR) and asserts pointer
// stability (interning cache is contract, not just optimisation).
//
// Under 32-bit FEX pre-fix: strings truncated to garbage via silent 32-bit
// address narrowing (Host.h::host_to_guest_convertible for pointers).
// Post-fix: all strings readable and repeat calls stable.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <X11/Xlib.h>
#define GL_GLEXT_PROTOTYPES 1
#include <GL/gl.h>
#include <GL/glext.h>
#include <GL/glx.h>

static const char* safe(const char* s) { return s ? s : "<null>"; }
static const char* safe_u(const GLubyte* s) { return s ? (const char*)s : "<null>"; }

int main(void) {
  Display* dpy = XOpenDisplay(NULL);
  if (!dpy) {
    fprintf(stderr, "XOpenDisplay failed\n");
    return 1;
  }

  int screen = DefaultScreen(dpy);

  printf("=== glX*String (before context) ===\n");
  printf("glXGetClientString(GLX_VENDOR):     %s\n", safe(glXGetClientString(dpy, GLX_VENDOR)));
  printf("glXGetClientString(GLX_VERSION):    %s\n", safe(glXGetClientString(dpy, GLX_VERSION)));
  printf("glXQueryServerString(GLX_VENDOR):   %s\n", safe(glXQueryServerString(dpy, screen, GLX_VENDOR)));
  printf("glXQueryServerString(GLX_VERSION):  %s\n", safe(glXQueryServerString(dpy, screen, GLX_VERSION)));
  {
    const char* ext = glXQueryExtensionsString(dpy, screen);
    printf("glXQueryExtensionsString: %.120s%s\n", safe(ext), (ext && strlen(ext) > 120) ? "..." : "");
  }

  int fb_attrs[] = {GLX_RGBA, GLX_DEPTH_SIZE, 24, GLX_DOUBLEBUFFER, None};
  XVisualInfo* vi = glXChooseVisual(dpy, screen, fb_attrs);
  if (!vi) {
    fprintf(stderr, "glXChooseVisual failed\n");
    return 2;
  }

  GLXContext ctx = glXCreateContext(dpy, vi, NULL, GL_TRUE);
  if (!ctx) {
    fprintf(stderr, "glXCreateContext failed\n");
    return 3;
  }

  Window root = RootWindow(dpy, screen);
  XSetWindowAttributes swa;
  swa.colormap = XCreateColormap(dpy, root, vi->visual, AllocNone);
  swa.event_mask = ExposureMask;
  Window win = XCreateWindow(dpy, root, 0, 0, 8, 8, 0, vi->depth, InputOutput,
                             vi->visual, CWColormap | CWEventMask, &swa);

  if (!glXMakeCurrent(dpy, win, ctx)) {
    fprintf(stderr, "glXMakeCurrent failed\n");
    return 4;
  }

  printf("\n=== glGetString ===\n");
  const GLubyte* v = glGetString(GL_VENDOR);
  const GLubyte* r = glGetString(GL_RENDERER);
  const GLubyte* ver = glGetString(GL_VERSION);
  const GLubyte* glsl = glGetString(GL_SHADING_LANGUAGE_VERSION);
  printf("GL_VENDOR:                   %s\n", safe_u(v));
  printf("GL_RENDERER:                 %s\n", safe_u(r));
  printf("GL_VERSION:                  %s\n", safe_u(ver));
  printf("GL_SHADING_LANGUAGE_VERSION: %s\n", safe_u(glsl));

  printf("\n=== glGetStringi(GL_EXTENSIONS, 0..2) ===\n");
  {
    GLint n = 0;
    glGetIntegerv(GL_NUM_EXTENSIONS, &n);
    printf("GL_NUM_EXTENSIONS = %d\n", n);
    for (GLuint i = 0; i < (GLuint)(n < 3 ? n : 3); ++i) {
      const GLubyte* e = glGetStringi(GL_EXTENSIONS, i);
      printf("  [%u] %s\n", i, safe_u(e));
    }
  }

  printf("\n=== pointer stability (interning cache) ===\n");
  const GLubyte* v2 = glGetString(GL_VENDOR);
  const GLubyte* v3 = glGetString(GL_VENDOR);
  printf("v=%p  v2=%p  v3=%p  %s\n", (void*)v, (void*)v2, (void*)v3,
         (v == v2 && v2 == v3) ? "STABLE" : "DIFFERENT (interning cache missing)");

  glXMakeCurrent(dpy, None, NULL);
  glXDestroyContext(dpy, ctx);
  XDestroyWindow(dpy, win);
  XCloseDisplay(dpy);
  return 0;
}
