// The GTK 3 C headers that Swift code imports as the module CGtk (see module.modulemap).
// Linux only; the headers and the libraries come from the distribution's libgtk-3-dev,
// found through pkg-config.
#include <gtk/gtk.h>
#include <string.h>

// Swift cannot call C macros or functions with variable arguments. The few of those the
// prompt needs are wrapped here.

// g_signal_connect() is a macro around this call.
static inline gulong phido2_signal_connect(gpointer instance, const char *signal,
                                           GCallback handler, gpointer data) {
    return g_signal_connect_data(instance, signal, handler, data, NULL, (GConnectFlags)0);
}

// Whether the prompt should be dark: the desktop asks applications for a dark appearance,
// or the theme in use is a dark one. The GTK_THEME environment variable, GTK's own way of
// overriding the theme (as in GTK_THEME=Adwaita:dark), counts as well.
// g_object_get() takes variable arguments.
static inline gboolean phido2_prefers_dark_theme(void) {
    gboolean dark = FALSE;
    gchar *theme = NULL;
    const gchar *override = g_getenv("GTK_THEME");
    g_object_get(gtk_settings_get_default(),
                 "gtk-application-prefer-dark-theme", &dark,
                 "gtk-theme-name", &theme, NULL);
    if (!dark && theme != NULL)
        dark = strstr(theme, "dark") != NULL || strstr(theme, "Dark") != NULL;
    if (!dark && override != NULL)
        dark = strstr(override, "dark") != NULL || strstr(override, "Dark") != NULL;
    g_free(theme);
    return dark;
}
