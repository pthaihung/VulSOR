#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "clang/Basic/Diagnostic.h"
#include "clang/Basic/DiagnosticOptions.h"
#include "clang/Driver/Compilation.h"
#include "clang/Driver/Driver.h"
#include "llvm/Support/VirtualFileSystem.h"

namespace {

constexpr const char* CLANG_PATH =
    "D:/DOWNLOAD/msys64/mingw64/bin/clang.exe";

// TODO: replace with an existing source file from the project.
constexpr const char* SOURCE_FILE =
    "D:/VulA/tests/fixtures/simple.cpp";

}  // namespace

int main() {
    std::cerr << "[1] probe started\n";

    clang::DiagnosticOptions diagnostic_options;

    clang::DiagnosticsEngine diagnostics(
        new clang::DiagnosticIDs(),
        diagnostic_options
    );

    std::cerr << "[2] diagnostics created\n";

    std::vector<std::string> arguments = {
        CLANG_PATH,
        "-c",
        SOURCE_FILE,
        "-std=c11",
    };

    std::vector<const char*> argument_pointers;
    argument_pointers.reserve(arguments.size());

    for (const std::string& argument : arguments) {
        argument_pointers.push_back(argument.c_str());
    }

    std::cerr << "[3] creating real VFS\n";

    auto vfs = llvm::vfs::getRealFileSystem();

    std::cerr << "[4] VFS created\n";

    std::cerr << "[5] creating driver\n";

    clang::driver::Driver driver(
        argument_pointers[0],
        "x86_64-w64-mingw-gnu",
        diagnostics,
        "clang LLVM compiler",
        vfs
    );

    std::cerr << "[6] driver created\n";

    driver.setCheckInputsExist(true);

    std::cerr << "[7] before BuildCompilation\n";

    std::unique_ptr<clang::driver::Compilation> compilation(
        driver.BuildCompilation(argument_pointers)
    );

    std::cerr << "[8] after BuildCompilation\n";

    if (!compilation) {
        std::cerr << "[9] compilation is null\n";
        return 1;
    }

    std::cerr << "[9] compilation created\n";

    std::cout << "VulSOR Driver probe: PASS\n";

    return 0;
}