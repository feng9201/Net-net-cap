#include "src\MyNetDump.h"
#include <QtWidgets/QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MyNetDump w;
    w.show();
    return a.exec();
}
