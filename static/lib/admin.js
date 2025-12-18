"use strict";

define("admin/plugins/sso-vk", ["settings", "alerts"], function (
  Settings,
  alerts,
) {
  var ACP = {};

  ACP.init = function () {
    Settings.load("sso-vk", $(".sso-vk-settings"));

    $("#save").on("click", function () {
      Settings.save("sso-vk", $(".sso-vk-settings"), function () {
        alerts.alert({
          type: "success",
          alert_id: "sso-vk-saved",
          title: "Settings Saved",
          message: "Please reload your NodeBB to apply these settings",
          clickfn: function () {
            socket.emit("admin.reload");
          },
        });
      });
    });
  };

  return ACP;
});
