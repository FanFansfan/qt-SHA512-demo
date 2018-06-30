import QtQuick 2.11
import QtQuick.Window 2.11
import QtQuick.Controls 2.3
import QtQuick.Dialogs.qml 1.0
import QtQuick.Extras 1.4
import QtQuick.Dialogs 1.3

Window {
    visible: true
    width: 640
    height: 480
    title: qsTr("SHA-512 Demo")

    Button {
        id: buttonDigest
        x: 497
        y: 155
        text: qsTr("Digest")
        onClicked: {
            if(radioButtonText.checked)
            {
                sha.update(textAreaSHAtext.text)
                textSHAdigest.text = sha.hexdigest().toUpperCase()
            }
            else
            {
                if(!textSHAfile.text)
                    return
                sha.updateFile(textSHAfile.text)
                textSHAdigest.text = sha.hexdigest().toUpperCase()
            }
        }
    }

    ScrollView {
        id: scrollView
        x: 73
        y: 22
        width: 412
        height: 40

        TextArea {
            id: textAreaSHAtext
            x: 0
            y: 0
            text: qsTr("Hello world!")
            wrapMode: Text.WrapAnywhere
            selectByMouse: true
        }
    }

    Text {
        id: textSHAfile
        x: 73
        y: 88
        width: 412
        height: 26
        elide: Text.ElideMiddle
        font.pixelSize: 12
    }

    Label {
        id: labelSHAText
        x: 10
        y: 34
        text: qsTr("Text:")
    }

    Label {
        id: labelSHAfile
        x: 10
        y: 93
        text: qsTr("File:")
    }

    RadioButton {
        id: radioButtonText
        x: 41
        y: 155
        width: 138
        height: 40
        checked: true
        text: qsTr("Text Digest")
    }

    RadioButton {
        id: radioButtonFile
        x: 266
        y: 155
        text: qsTr("File Digest")
    }

    Text {
        id: textSHAdigest
        x: 42
        y: 291
        width: 556
        height: 103
        text: qsTr("")
        wrapMode: Text.WrapAnywhere
        font.pixelSize: 12
    }

    Label {
        id: labelDigest
        x: 41
        y: 260
        width: 58
        height: 19
        text: qsTr("Digest:")
    }

    Button {
        id: buttonOpenFile
        x: 497
        y: 93
        text: qsTr("Open File")
        onClicked: {
            fileDialog.open()
        }
    }

    FileDialog {
        id: fileDialog
        title: qsTr("Open file")
        folder: shortcuts.home
        onAccepted: {
            textSHAfile.text = fileDialog.fileUrl
        }
    }
}
