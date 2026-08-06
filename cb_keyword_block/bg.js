browser.runtime.onMessage.addListener(function (msg, sender) {
  if (msg && msg.cmd === "close-tab" && sender.tab && sender.tab.id != null) {
    browser.tabs.remove(sender.tab.id).catch(function () {});
  }
});
