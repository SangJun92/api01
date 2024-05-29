package org.zerock.api01.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Service;
import org.zerock.api01.domain.Todo;
import org.zerock.api01.dto.TodoDTO;
import org.zerock.api01.repository.TodoRepository;

@Service
@RequiredArgsConstructor
@Log4j2
public class TodoServiceImpl implements TodoService {

    private final TodoRepository todoRepository;
    private final ModelMapper modelMapper;


    @Override
    public Long register(TodoDTO todoDTO) {

        Todo todo = modelMapper.map(todoDTO, Todo.class);

        Long tno = todoRepository.save(todo).getTno();

        return tno;
    }
}
