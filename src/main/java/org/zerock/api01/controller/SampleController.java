package org.zerock.api01.controller;

import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("/api/sample")
public class SampleController {

    @Tag(name="Sample Get do A")
    @GetMapping("/doA")
    public List<String> doA(){
        return Arrays.asList("AAA", "BBB", "CCC");
    }
}
